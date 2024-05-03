import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"source IP :{src_ip}|Destination IP :{dst_ip}|protocol:{protocol}")
        if packet.haslayer(scapy.TCP):
            try:
                payload = packet [scapy.raw].load
                decoded_payload=payload.decode('utf-8','ignore')
                print(f"TCP payload")
            except(IndexError,UnicodeDecodeError):
                print("unable to decode TCP payload.")
        elif packet.haslayer(scapy.UDP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload=payload.decode('utf-8','ignore')
             except(IndexError,UnicodedecodeError):
                 print("unable to decode UDP payload.")

def start_sniffing():
    scapy.sniff(store=False,prn=packet_callback)
    
start_sniffing()    