import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")
        
        if packet.haslayer(scapy.TCP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"TCP Payload (first 50 characters): {decoded_payload[:50]}")
            except (IndexError, UnicodeDecodeError):
                print("Unable to decode TCP payload.")
                
           
                
def start_sniffing():
    scapy.sniff(store=False, prn=packet_callback)
    
start_sniffing()



                        


# HELLO EVERYONE...   I HAVE WRITTEN A PYTHON CODE FOR NETWORK PACKET SNIFFER

#  STEPS : 1. IMPORT SCAPY
          #2. DEFINE CALLBACK FUNCTION
          #3. SOURCE/DENSTINATION IP'S AND PROTOCOL DEFINED
          #4. PRINT THAT ALL
          #5. NOW WE SCAN FOR "TCP" PACKETS ONLY    HERE WE CAN USE MORE PROTOCOLS HTTP/HTTPS/ICMP/POP3/ETC...
          #6. PAYLOAD SIZE DECLARATION AND TRY/EXCEPT CONDITION
          #7. START SNIFFING FUNCTION DEFINED AND SNIFFING STARTED 

# THIS IS THE SIMPLE PYTHON CODE FOR NETWORK SNIFFER TOOL

# ANYONE CAN ABLE TO ADD OR REMOVE FUNCTIONALITY AS WE WANT INTO THIS CODE 
 
