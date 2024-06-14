import sys
# import socket
import threading, time
from scapy.all import *

def decode_payload(pkt):
    return {i.split(':')[0].strip():i.split(':')[1].strip() for i in [p.strip() for p in pkt[Raw].load.decode('utf-8').split('|')]}

class EAP_AP():
    def __init__(self, channel: int, security:str = "EAP-TLS") -> None:
        self.channel = channel
        self.security = security
        self.broadcasting = True
        self.target_sta = {
            'found': False,
            'wait_for': False
        }
        self.usage = dict()
        self.setup()

    def setup(self):
        # Create broadcasting thread
        self.usage = {
            'seq_num': 0,
            # WIFI (simulated)
            'AP_SSID': "EAP_AP",
            'AP_CHANNEL': self.channel,
            'AP_RATE': 1,
            # ETHERNET
            'port': 1000 + self.channel - 1,
            'dst_port': 1000 + self.channel,
        }
        print(f"AP<{get_if_addr(conf.iface)}:{self.usage['port']}> Setup", '\n')
        self.broadcast_thread = threading.Thread(target=lambda: self.broadcast_beacon(interval=3), daemon=True)
        self.broadcast_thread.start()
    
    def start(self):
        # Start broadcasting thread
        print(f"AP start Boardcasting at Channel: {self.channel}", '\n')
        while not self.target_sta['found']:
            sniff(prn=self.handle_request,
                filter=f"udp and ether dst host ff:ff:ff:ff:ff:ff and port {self.usage['port']}",
                iface="lo",
                count=1)
        self.broadcast_thread.join()
        self.target_sta['wait_for'] = True

        # Probe Response
        while self.target_sta['wait_for']:
            self.send_probe_response()
            sniff(prn=self.handle_authentication_request,
                  filter=f"udp and ether dst host ff:ff:ff:ff:ff:ff and port {self.usage['port']}",
                  iface="lo",
                  timeout=1, # timer
                  count=1)
        self.target_sta['wait_for'] = True

        # Authentication Response
        while self.target_sta['wait_for']:
            self.send_authentication_response()
            sniff(prn=self.handle_association_requset,
                  filter=f"udp and ether dst host ff:ff:ff:ff:ff:ff and port {self.usage['port']}",
                  iface="lo",
                  timeout=1, # timer
                  count=1)
        self.target_sta['wait_for'] = True

        # Association Response
        while self.target_sta['wait_for']:
            self.send_association_response()
            sniff(prn=self.wait_for_eap_tls,
                  filter=f"ether dst host ff:ff:ff:ff:ff:ff and port {self.usage['port']}",
                  iface="lo",
                  timeout=1, # timer
                  count=1)
        self.target_sta['wait_for'] = True

        # Start EAP process with target STA
        self.eap_tls()

    def broadcast_beacon(self, interval: float):
        # Send boardcasting packet
        while self.broadcasting:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") /\
                     IP(dst="255.255.255.255") /\
                     UDP(dport=self.usage['dst_port'], sport=self.usage['port']) /\
                     Raw(load=" | ".join(["frame_type: Beacon",
                                          f"port: {self.usage['port']}",
                                          f"dst_port: {self.usage['dst_port']}"]))
            sendp(packet, iface="lo", verbose=False)
            print(f"AP broadcast(seq:{self.usage['seq_num']}):", packet, '\n')
            self.usage['seq_num'] += 1
            time.sleep(interval) # Broadcast interval
       
    def handle_request(self, pkt):
        if pkt.haslayer(Raw): 
            try:
                payload = decode_payload(pkt)
                if payload.get('frame_type', '') == 'Request':
                    print("Received Request Packet:", payload, '\n')
                    self.target_sta['found'] = True
                    self.target_sta['addr'] = payload['addr']
                    self.broadcasting = False
            except Exception as e:
                print(f"*** Error Processing Request Packet: {e}", '\n')
                sys.exit(1)

    def send_probe_response(self):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") /\
                 IP(dst="255.255.255.255") /\
                 UDP(dport=self.usage['dst_port'], sport=self.usage['port']) /\
                 Raw(load=" | ".join(["frame_type: Response",
                                     f"dst: {self.target_sta['addr']}"]+ 
                                     [f"{k}: {self.usage[k]}" for k in self.usage]))
        sendp(packet, iface="lo", verbose=False)
        print(f"AP send Probe-Response(seq:{self.usage['seq_num']}):", packet, '\n')
        self.usage['seq_num'] += 1

    def handle_authentication_request(self, pkt):
        if pkt.haslayer(Raw):
            try:
                payload = decode_payload(pkt)
                if int(payload.get('STA_CHANNEL', -1)) == self.channel and \
                   payload.get('SSID', '') == self.usage['AP_SSID'] and \
                   payload.get('frame_type', '') == 'Request':
                    print("Received Authentication Request Packet:", payload, '\n')
                    self.target_sta['wait_for'] = False
                    self.target_sta['seq_num'] = payload['seq_num']
                    self.target_sta['SSID'] = payload['STA_SSID']
            except Exception as e:
                print(f"*** Error Processing Authentication Packet: {e}", '\n')
                sys.exit(1)

    def send_authentication_response(self):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") /\
                 IP(dst="255.255.255.255") /\
                 UDP(dport=self.usage['dst_port'], sport=self.usage['port']) /\
                 Raw(load=" | ".join(["frame_type: Response",
                                     f"dst: {self.target_sta['addr']}",
                                     f"response: {int(True)}"]+ 
                                     [f"{k}: {self.usage[k]}" for k in self.usage]))
        sendp(packet, iface="lo", verbose=False)
        print(f"AP send Authentication-Response(seq:{self.usage['seq_num']}):", packet, '\n')
        self.usage['seq_num'] += 1

    def handle_association_requset(self, pkt):
        if pkt.haslayer(Raw):
            try:
                payload = decode_payload(pkt)
                if payload.get('frame_type', '') == 'Request' and \
                   payload.get('STA_SSID', '') == self.target_sta['SSID'] and \
                   self.target_sta['seq_num'] != payload['seq_num']:
                    print("Received Association Request Packet:", payload, '\n')
                    self.target_sta['wait_for'] = False
                    self.target_sta['seq_num'] = payload['seq_num']
            except Exception as e:
                print(f"*** Error Processing Association Packet: {e}", '\n')
                sys.exit(1)

    def send_association_response(self):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") /\
                 IP(dst="255.255.255.255") /\
                 UDP(dport=self.usage['dst_port'], sport=self.usage['port']) /\
                 Raw(load=" | ".join(["frame_type: Response",
                                     f"dst: {self.target_sta['addr']}",
                                     f"response: {int(True)}",
                                     f"assosiation: DONE"]+ 
                                     [f"{k}: {self.usage[k]}" for k in self.usage]))
        sendp(packet, iface="lo", verbose=False)
        print(f"AP send Association-Response(seq:{self.usage['seq_num']}):", packet, '\n')
        self.usage['seq_num'] += 1

    def wait_for_eap_tls(self, pkt):
        if pkt.haslayer(Raw):#
            try:
                payload = decode_payload(pkt)
                if payload.get('frame_type', '') == self.security and \
                   payload.get('STA_SSID', '') == self.target_sta['SSID'] and \
                   payload.get('code', '') == 'START' and \
                   self.target_sta['seq_num'] != payload['seq_num']:
                    print("Received EAP-START Packet:", payload, '\n')
                    self.target_sta['wait_for'] = False
                    self.target_sta['seq_num'] = payload['seq_num']
            except Exception as e:
                print(f"*** Error Processing EAPOL-START Packet: {e}", '\n')
                sys.exit(1)

    def eap_tls(self):
        # ...
        print("AP Ready for EAP_TLS ...", '\n')
        pass


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: EAP_AP <CHANNEL_NUMBER>", '\n')
    else:
        try:
            argv_channel = int(sys.argv[1])
        except Exception as e:
            argv_channel = 1
            print("Error: integer <CHANNEL_NUMBER>")
            print(f"Usage: CHANNEL_NUMBER-{argv_channel}", '\n')

    # Wifi-AP simulation on loopback interface
    AP = EAP_AP(channel=argv_channel)
    AP.start()
