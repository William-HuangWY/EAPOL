import sys
# import socket
import threading, time
from scapy.all import *

class EAP_AP():
    def __init__(self, port: int, dest_port: int) -> None:
        self.port = port
        self.dest_port = dest_port
        self.setup()

    def setup(self):
        # Create broadcasting thread
        self.broadcast_thread = threading.Thread(target=lambda: self.broadcast_beacon(interval=3), daemon=True)
        self.broadcast_thread.start()
        print(f"AP<{get_if_addr(conf.iface)}:{self.port}> Setup", '\n')
    
    def start(self):
        # Start broadcasting thread
        print(f"AP start boardcasting at: {self.dest_port}", '\n')
        
        # while True:
        #     self.handle_signal()
        self.broadcast_thread.join()

    def broadcast_beacon(self, interval: float):
        # Send boardcasting packet
        while True:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") /\
                     IP(dst="255.255.255.255") /\
                     UDP(dport=self.dest_port, sport=self.port) /\
                     Raw(load="Beacon")
            sendp(packet, iface="lo", verbose=False)
            print("AP broadcast:", packet, '\n')
            time.sleep(interval) # Broadcast interval

    def handle_signal(self):
        print("(handle_signal)", '\n')
        pass

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

    # Wifi-AP simulation on loopback interface
    AP = EAP_AP(port=argv_port, dest_port=argv_dest_port) 
    AP.start()
