from scapy.all import *
from colorama import Fore, init
from datetime import datetime

#colorama
init(autoreset=True)

packet_count = 0

LOG_FILE = "packets.log"

def log_to_file(data):
    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(data + "\n")
        
def process_packet(packet):
    global packet_count
    packet_count += 1
    
    print(Force.CYAN + "\n===================================")
    print(Force.YELLOW + f"Packet Number: {packet_count}")
    print(Force.GREEN + f"Time: {datetime.now()}")
    
    log_data = f"\nPacket #{packet_count}\n"
    log_data += f"Time: {datetime.now()}\n"
    
#IP packets
    
if packet.haslayer(IP):
    ip_layer = packet[IP]
    
    src_ip = ip_layer.src
    dst_ip = ip_layer.src
    
    print(Force.BLUE + f"source ip: {src_ip}")
    print(Force.BLUE + f"destination ip: {dst_ip}")
    log_data += f"Source IP: {src_ip}\n"
    log_data += f"Destination IP: {dst_ip}\n"
    
#TCP

if packet.haslayer(TCP):
    tcp_layer = packet[TCP]
    
    print(Force.MAGENTA + "[Protocol] TCP")
    print(f"Source port: {tcp.layer.sport}")
    print(f"Destination port: {tcp.layer.dport}")
    
    log_data += "Protocol: TCP\n"
    log_data += f"Source Port: {tcp_layer.sport}\n"
    log_data += f"Destination Port: {tcp_layer.dport}\n"
    
#UDP

