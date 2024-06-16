import sys
# import socket
# import binascii
from scapy.all import *

def decode_payload(pkt):
    return {i.split(':')[0].strip():i.split(':')[1].strip() for i in [p.strip() for p in pkt[Raw].load.decode('utf-8').split('|')]}

class EAP_STA():
    def __init__(self, security:str = 'EAP-TLS') -> None:
        self.security = security
        self.usage = dict()
        self.target_ap = {
            'found': False,
            'wait_for': False,
        }
        self.setup()

    def setup(self):
        self.usage = {
            'seq_num': 0,
            # WIFI (simulated)
            'STA_SSID': "EAP_STA",
            'STA_CHANNEL': None,
            # ETHERNET
            'port': None,
            'dst_port': None,
        }
        print(f"STA<{get_if_addr(conf.iface)}> Setup", '\n')

    def start(self):
        print("STA started listening for beacon frames ...", '\n')
        while not self.target_ap['found']:
            self.sniff_beacon()
        self.target_ap['wait_for'] = True

        # Probe Request
        while self.target_ap['wait_for']:
            self.send_probe_request()
            sniff(prn=self.handle_probe_response,
                  filter=f"udp and ether dst host ff:ff:ff:ff:ff:ff and port {self.usage['port']}",
                  iface="lo",
                  timeout=1, # timer
                  count=1)
        self.target_ap['wait_for'] = True

        # Authentication Request
        while self.target_ap['wait_for']:
            self.send_authentication_request()
            sniff(prn=self.handle_authentication_response,
                  filter=f"udp and ether dst host ff:ff:ff:ff:ff:ff and port {self.usage['port']}",
                  iface="lo",
                  timeout=1, # timer
                  count=1)
        self.target_ap['wait_for'] = True

        # Association Request
        while self.target_ap['wait_for']:
            self.send_association_requset()
            sniff(prn=self.handle_authentication_response,
                  filter=f"udp and ether dst host ff:ff:ff:ff:ff:ff and port {self.usage['port']}",
                  iface="lo",
                  timeout=1, # timer
                  count=1)
        self.target_ap['wait_for'] = True

        # Start EAP process with target AP
        self.eap_tls()

    def sniff_beacon(self):
        sniff(prn=self.handle_beacon,
                  filter=f"udp and ether dst host ff:ff:ff:ff:ff:ff",
                  iface="lo",
                  count=1)

    def handle_beacon(self, pkt):
        if pkt.haslayer(Raw): 
            try:
                payload = decode_payload(pkt)
                if payload.get('frame_type', '') == 'Beacon':
                    print("Received Beacon:", payload, '\n')
                    self.target_ap['found'] = True
                    self.usage['port'] = int(payload['dst_port'])
                    self.usage['dst_port'] = int(payload['port'])
            except Exception as e:
                print(f"*** Error Processing Beacon Packet: {e}", '\n')
                sys.exit(1)

    def send_probe_request(self):
        # Create a probe request packet
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") /\
                 IP(dst="255.255.255.255") /\
                 UDP(dport=self.usage['dst_port'], sport=self.usage['port']) /\
                 Raw(load=" | ".join(["frame_type: Request",
                                      f"addr: {get_if_addr(conf.iface)}"]))
        sendp(packet, iface="lo", verbose=False)
        print(f"STA send Probe-Request(seq:{self.usage['seq_num']}):", packet, '\n')
        self.usage['seq_num'] += 1

    def handle_probe_response(self, pkt):
        if pkt.haslayer(Raw): 
            try:
                payload = decode_payload(pkt)
                if payload.get('dst', '') == get_if_addr(conf.iface) and \
                   payload.get('frame_type', '') == 'Response':
                    print(f"Received Response: {payload}", '\n')
                    self.target_ap['wait_for'] = False
                    self.target_ap['seq_num'] = payload['seq_num']
                    self.target_ap['SSID'] = payload['AP_SSID']
                    self.target_ap['RATE'] = payload['AP_RATE']
                    self.usage['STA_CHANNEL'] = payload['AP_CHANNEL']
            except Exception as e:
                print(f"*** Error Processing Response Packet: {e}", '\n')
                sys.exit(1)

    def send_authentication_request(self):
        # Create a authentication request packet
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") /\
                 IP(dst="255.255.255.255") /\
                 UDP(dport=self.usage['dst_port'], sport=self.usage['port']) /\
                 Raw(load=" | ".join(["frame_type: Request", f"SSID: {self.target_ap['SSID']}"]+
                                     [f"{k}: {self.usage[k]}" for k in self.usage]))
        sendp(packet, iface="lo", verbose=False)
        print(f"STA send Authentication-Request(seq:{self.usage['seq_num']}):", packet, '\n')
        self.usage['seq_num'] += 1

    def handle_authentication_response(self, pkt):
        if pkt.haslayer(Raw): 
            try:
                payload = decode_payload(pkt)
                if payload.get('AP_SSID', '') == self.target_ap['SSID'] and \
                   payload.get('dst', '') == get_if_addr(conf.iface) and \
                   payload.get('frame_type', '') == 'Response' and int(payload.get('response', '0')) and \
                   self.target_ap['seq_num'] != payload['seq_num']:
                    print(f"Received Authentication Response: {payload}", '\n')
                    self.target_ap['wait_for'] = False
                    self.target_ap['seq_num'] = payload['seq_num']
            except Exception as e:
                print(f"*** Error Processing Authentication Packet: {e}", '\n')
                sys.exit(1)

    def send_association_requset(self):
        # Create a association request packet
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") /\
                 IP(dst="255.255.255.255") /\
                 UDP(dport=self.usage['dst_port'], sport=self.usage['port']) /\
                 Raw(load=" | ".join(["frame_type: Request",
                                      f"rsn: {self.security}"]+
                                      [f"{k}: {self.usage[k]}" for k in self.usage]))
        sendp(packet, iface="lo", verbose=False)
        print(f"STA send Association-Request(seq:{self.usage['seq_num']}):", packet, '\n')
        self.usage['seq_num'] += 1

    def handle_association_response(self, pkt):
        if pkt.haslayer(Raw): 
            try:
                payload = decode_payload(pkt)
                if payload.get('assosiation', '') == 'DONE' and \
                   payload.get('AP_SSID', '') == self.target_ap['SSID'] and \
                   payload.get('dst', '') == get_if_addr(conf.iface) and \
                   payload.get('frame_type', '') == 'Response' and int(payload.get('response')) and \
                   self.target_ap['seq_num'] != payload['seq_num']:
                    print(f"Received Association Response: {payload}", '\n')
                    self.target_ap['wait_for'] = False
                    self.target_ap['seq_num'] = payload['seq_num']
            except Exception as e:
                print(f"*** Error Processing Association Packet: {e}", '\n')
                sys.exit(1)

    def eap_tls(self):
        print(f'<<< Start EAP-TLS with AP(ssid:{self.target_ap["SSID"]}) >>>', '\n')
        
        # EAP-Start
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") /\
                 IP(dst="255.255.255.255") /\
                 TCP(dport=self.usage['dst_port'], sport=self.usage['port']) /\
                 Raw(load=" | ".join([f"frame_type: {self.security}",
                                      f"code: START",
                                      f"message: ClientHello"]+
                                      [f"{k}: {self.usage[k]}" for k in self.usage]))
        sendp(packet, iface="lo", verbose=False)
        print(f"STA send EAPOL-START(seq:{self.usage['seq_num']}):", packet, '\n')
        self.usage['seq_num'] += 1

        ##### HandShake #####
        # Receive HandShake Data
        pkt = sniff(filter=f"ether dst host ff:ff:ff:ff:ff:ff and port {self.usage['port']}", count=1)[0]

        if pkt.haslayer(Raw):
            try:
                payload = decode_payload(pkt)
                if payload.get('frame_type', '') == 'EAP-TLS' and \
                payload.get('code', '') == 'HandShake' and \
                payload.get('message', '') == 'ServerHello':
                    
                    print(f"Received HandShake Data: {payload}", '\n')
                    
                    # Convert received data from hex
                    iv = binascii.unhexlify(payload['iv'])
                    bls_public_key = binascii.unhexlify(payload['pbk'])
                    encrypted_payload = binascii.unhexlify(payload['tls_data'])

                    # Generate ECDHE key pair
                    sta_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                    sta_public_key = sta_private_key.public_key()

                    # Load AP's ECDHE public key from received data
                    ap_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), bls_public_key)

                    # Generate the shared key using the received ECDHE public key
                    shared_key = sta_private_key.exchange(ec.ECDH(), ap_public_key)

                    # Derive AES key from the shared key
                    aes_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data',
                    ).derive(shared_key)

                    # Decrypt the payload
                    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    decrypted_data = decryptor.update(encrypted_payload) + decryptor.finalize()

                    # Remove padding
                    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

                    # Extract the ECDHE public key and the signature
                    public_key_len = len(decrypted_data) - 96  # BLS signature size is 96 bytes
                    received_public_key = decrypted_data[:public_key_len]
                    received_signature = decrypted_data[public_key_len:]

                    # Verify the signature
                    if bls.Verify(ap_public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo), received_public_key, received_signature):
                        print("Signature is valid")
                    else:
                        print("Signature is invalid")
            
            except Exception as e:
                print(f"*** Error Processing HandShake Packet: {e}", '\n')
                traceback.print_exc()
                sys.exit(1)


if __name__ == '__main__':
    # Wifi-STA simulation on loopback interface
    STA = EAP_STA()
    STA.start()
