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