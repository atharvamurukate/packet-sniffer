from scapy.all import *
from colorama import Fore, init
from datetime import datetime

# Initialize colorama
init(autoreset=True)

packet_count = 0

LOG_FILE = "packets.log"


def log_to_file(data):
    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(data + "\n")


def process_packet(packet):
    global packet_count

    packet_count += 1

    print(Fore.CYAN + "\n===================================")
    print(Fore.YELLOW + f"Packet Number: {packet_count}")
    print(Fore.GREEN + f"Time: {datetime.now()}")

    log_data = f"\nPacket #{packet_count}\n"
    log_data += f"Time: {datetime.now()}\n"

    # ---------------- IP PACKETS ---------------- #

    if packet.haslayer(IP):

        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        print(Fore.BLUE + f"Source IP: {src_ip}")
        print(Fore.BLUE + f"Destination IP: {dst_ip}")

        log_data += f"Source IP: {src_ip}\n"
        log_data += f"Destination IP: {dst_ip}\n"

        # ---------------- TCP ---------------- #

        if packet.haslayer(TCP):

            tcp_layer = packet[TCP]

            print(Fore.MAGENTA + "[Protocol] TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")

            log_data += "Protocol: TCP\n"
            log_data += f"Source Port: {tcp_layer.sport}\n"
            log_data += f"Destination Port: {tcp_layer.dport}\n"

        # ---------------- UDP ---------------- #

        elif packet.haslayer(UDP):

            udp_layer = packet[UDP]

            print(Fore.MAGENTA + "[Protocol] UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

            log_data += "Protocol: UDP\n"
            log_data += f"Source Port: {udp_layer.sport}\n"
            log_data += f"Destination Port: {udp_layer.dport}\n"

        # ---------------- ICMP ---------------- #

        elif packet.haslayer(ICMP):

            print(Fore.MAGENTA + "[Protocol] ICMP")

            log_data += "Protocol: ICMP\n"

        # ---------------- DNS Monitoring ---------------- #

        if packet.haslayer(DNS) and packet[DNS].qd:

            try:
                dns_query = packet[DNS].qd.qname.decode()

                print(Fore.RED + f"[DNS Query] {dns_query}")

                log_data += f"DNS Query: {dns_query}\n"

            except:
                pass

        # ---------------- HTTP Packet Inspection ---------------- #

        if packet.haslayer(Raw):

            try:
                payload = packet[Raw].load.decode(errors="ignore")

                # Detect HTTP Requests
                if (
                    "HTTP" in payload
                    or "GET" in payload
                    or "POST" in payload
                ):

                    print(Fore.LIGHTGREEN_EX + "\n[HTTP Traffic Detected]")

                    log_data += "\nHTTP Traffic Detected\n"

                    lines = payload.split("\n")

                    for line in lines[:10]:

                        clean_line = line.strip()

                        if clean_line:

                            print(Fore.WHITE + clean_line)

                            log_data += clean_line + "\n"

            except:
                pass

    # ---------------- ARP Monitoring ---------------- #

    elif packet.haslayer(ARP):

        arp_layer = packet[ARP]

        print(Fore.LIGHTCYAN_EX + "[ARP Packet Detected]")

        print(f"Source MAC: {arp_layer.hwsrc}")
        print(f"Destination MAC: {arp_layer.hwdst}")
        print(f"Source IP: {arp_layer.psrc}")
        print(f"Destination IP: {arp_layer.pdst}")

        log_data += "ARP Packet Detected\n"
        log_data += f"Source MAC: {arp_layer.hwsrc}\n"
        log_data += f"Destination MAC: {arp_layer.hwdst}\n"
        log_data += f"Source IP: {arp_layer.psrc}\n"
        log_data += f"Destination IP: {arp_layer.pdst}\n"

    else:
        print(Fore.RED + "Other Packet Type")

    log_to_file(log_data)


print(Fore.GREEN + "================================================")
print(Fore.GREEN + "        ADVANCED PYTHON PACKET SNIFFER")
print(Fore.GREEN + "================================================")
print(Fore.YELLOW + "Features:")
print(Fore.YELLOW + "- TCP/UDP/ICMP Monitoring")
print(Fore.YELLOW + "- DNS Monitoring")
print(Fore.YELLOW + "- HTTP Packet Inspection")
print(Fore.YELLOW + "- ARP Monitoring")
print(Fore.YELLOW + "- Packet Logging")
print(Fore.YELLOW + "\nCapturing packets...")
print(Fore.YELLOW + "Press CTRL+C to stop.\n")

sniff(prn=process_packet, store=False)