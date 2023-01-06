#!/usr/bin/python3

from scapy.all import *

BPF_FILTER="tcp"

def handle_tcp(packet):
        # Check if the packet is a DNS query
        if not packet.haslayer(TCP):
            return
        send(packet, iface="ens33")


def init():
    global my_ip 
    global my_mac
    global gw_ip
    global gw_mac
    global src_ether
    conf.verb = 0
    my_ip = conf.route.route("0.0.0.0")[1]
    my_mac = Ether().src
    gw_ip = conf.route.route("0.0.0.0")[2]

    results, unanswered = sr(ARP(op=1, psrc=my_ip, pdst=gw_ip))
    gw_mac = results[0][1].hwsrc
    print(f"My ip: {my_ip}, my mac: {my_mac}, gw_ip: {gw_ip}, gw_mac: {gw_mac}")
    conf.verb = 1
    src_ether = Ether(src=my_mac, dst = gw_mac)

def main():
    init()
    sniff(filter=BPF_FILTER, iface="tun0", prn=handle_tcp)


if __name__ == '__main__':
    main()