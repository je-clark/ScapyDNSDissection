from scapy.all import *
import re


def extract_ips_from_packet(packet):
    packet_dict = {}
    query_name = packet[DNS].qd.qname
    if packet[DNS].qd.qtype == 1:
        for x in range(packet[DNS].ancount):
            if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',packet[DNS].an[x].rdata) == None:
                continue
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


def build_dns_dict(pcap):
    dns_dict = {}
    print("Iterating through packets now...")
    for packet in pcap:
        if (DNS in packet) and (packet[DNS].qr == 1):
            dns_dict.update(extract_ips_from_packet(packet))
    return dns_dict


if __name__ == "__main__":
    pcap_fn = sys.argv[1]
    pcap = rdpcap(pcap_fn)
    print("PCAP Loaded")

    dns_dict = build_dns_dict(pcap)
    for ip in dns_dict:
        print(ip)
        print("    %s" % dns_dict[ip][0])
        print("    %s" % dns_dict[ip][1])
