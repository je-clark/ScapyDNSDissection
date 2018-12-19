from scapy.all import *
import re

# Workhorse Function. Called for each DNS packet
def extract_ips_from_packet(packet):
    packet_dict = {}
    query_name = packet[DNS].qd.qname
    
    # A qtype of 1 refers to an A record request
    if packet[DNS].qd.qtype == 1:
        for x in range(packet[DNS].ancount):
            # If rdata doesn't contain an IP address, it's just chaining to another record
            # and I don't care about it.
            if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',packet[DNS].an[x].rdata) == None:
                continue
            # temp is a dictionary with the key being the IP address
            # and the value being a list including the record name and query name
            temp = {packet[DNS].an[x].rdata:[
                packet[DNS].an[x].rrname,
                query_name
            ]}
            packet_dict.update(temp)
        for x in range(packet[DNS].arcount):
            if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',packet[DNS].ar[x].rdata) == None:
                continue
            temp = {packet[DNS].ar[x].rdata:[
                packet[DNS].ar[x].rrname,
                query_name
            ]}
            packet_dict.update(temp)
            
    # A qtype of 33 refers to a SRV request
    if packet[DNS].qd.qtype == 33:
        for x in range(packet[DNS].arcount):
            if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',packet[DNS].ar[x].rdata) == None:
                continue
            temp = {packet[DNS].ar[x].rdata:[
                packet[DNS].ar[x].rrname,
                query_name
            ]}
            packet_dict.update(temp)
    return packet_dict

# Helper function filtering out non-DNS packets and maintaining the dictionary
def build_dns_dict(pcap):
    dns_dict = {}
    print("Iterating through packets now...")
    for packet in pcap:
        if (DNS in packet) and (packet[DNS].qr == 1):
            dns_dict.update(extract_ips_from_packet(packet))
    return dns_dict

# Primary function reading in the PCAP and printing the end result
if __name__ == "__main__":
    pcap_fn = sys.argv[1]
    pcap = rdpcap(pcap_fn)
    print("PCAP Loaded")

    dns_dict = build_dns_dict(pcap)
    for ip in dns_dict:
        print(ip)
        print("    %s" % dns_dict[ip][0])
        print("    %s" % dns_dict[ip][1])
