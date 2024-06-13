import sys
# import socket
from scapy.all import *

class EAP_STA():
    def __init__(self, port: int, dest_port: int) -> None:
        self.port = port
        self.dest_port = dest_port
        self.setup()

    def setup(self):
        print(f"STA<{get_if_addr(conf.iface)}:{self.port}> Setup", '\n')

    def start(self):
        print("STA started listening for beacon frames...", '\n')
        while True:
            sniff(prn=self.handle_beacon,
                  filter=f"udp and port {self.port}",
                  iface="lo")

    def handle_beacon(self, pkt):
        print(f"Received Packet Details: dest{pkt.dst}")
        if pkt.haslayer(Raw): print(pkt[Raw].load)
        print()
        # pkt.show()
        

    # def handle_beacon(self, pkt):
    #     if pkt.haslayer(Raw) and pkt[Raw].load == "Beacon":
    #         print("Received Beacon Frame from AP:")
    #         print(pkt.summary())  # Print a summary of the received packet
            
            # Process Frame
            # ...

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: EAP_AP <PORT_NUMBER> <DEST_PORT_NUMBER>", '\n')
        sys.exit(1)

    try:
        argv_port = int(sys.argv[1])
        argv_dest_port = int(sys.argv[2])
    except ValueError:
        print("Error: integer <PORT_NUMBER> <DEST_PORT_NUMBER>", '\n')
        sys.exit(1)
    
    # Wifi-STA simulation on loopback interface
    STA = EAP_STA(port=argv_port, dest_port=argv_dest_port) # loopback ip
    STA.start()
