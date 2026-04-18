from scapy.all import sniff, ARP
import os
import time
from scapy.interfaces import dev_from_index

ip_mac_mapping = {}

def get_mac(ip):
    """
    Helper function: In a real environment, you might actively ARP ping the IP 
    to get the true MAC, but here we learn dynamically from the network.
    """
    return ip_mac_mapping.get(ip)

def mitigate_attack(attacker_ip, attacker_mac):
    """
    Function 2: Alerting and Active Mitigation.
    Logs the attack and simulates blocking the compromised channel.
    """
    print(f"\n[!!!] MITIGATION TRIGGERED [!!!]")
    print(f"[*] Blocking compromised IP: {attacker_ip} and MAC: {attacker_mac}")
    
    # os.system(f"iptables -A INPUT -s {attacker_ip} -m mac --mac-source {attacker_mac} -j DROP")
    
    print("[*] Connection severed. Traffic from malicious node dropped.\n")

def process_packet(packet):
    """
    Function 1: ARP Spoofing Detection Logic.
    Analyzes captured ARP packets for unsolicited replies and MAC-IP mismatches.
    """
    if packet.haslayer(ARP):
        # op == 2 means it's an ARP Reply (is-at)
        if packet[ARP].op == 2:
            real_ip = packet[ARP].psrc
            response_mac = packet[ARP].hwsrc

            if real_ip in ip_mac_mapping:
                known_mac = ip_mac_mapping[real_ip]
                
                if known_mac != response_mac:
                    print(f"\n[ALERT] MITM ATTACK DETECTED! ARP Spoofing underway.")
                    print(f"[-] Legitimate MAC for {real_ip} is {known_mac}")
                    print(f"[-] Attacker is spoofing with MAC {response_mac}")
                    
                    # Trigger Mitigation
                    mitigate_attack(real_ip, response_mac)
            else:
                # If it's a new IP, learn the mapping (Baseline creation)
                ip_mac_mapping[real_ip] = response_mac      
                print(f"[+] Learned new mapping: IP {real_ip} -> MAC {response_mac}")

def start_sniffer(interface=None):
    """
    Starts the packet capture interface continuously in promiscuous mode.
    """
    print(f"[*] Starting MITM Detection Engine...")
    print(f"[*] Sniffing for ARP anomalies. Press Ctrl+C to stop.\n")
    sniff(store=False, prn=process_packet, filter="arp", iface=interface)

if __name__ == "__main__":
    # Convert your index number (9) into a Scapy interface object
    my_interface = dev_from_index(9) 
    
    # Pass the object to the sniffer
    start_sniffer(interface=my_interface)