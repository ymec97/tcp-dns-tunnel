#!/usr/bin/python3

from scapy.all import *
import logging

# create a logger with the name of the current module
logger = logging.getLogger(__name__)

# set the log level to debug
logger.setLevel(logging.DEBUG)

# create a console handler and set the log level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create a formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add the formatter to the console handler
ch.setFormatter(formatter)

# add the console handler to the logger
logger.addHandler(ch)

# log a message
logger.debug("This is a debug message.")
logger.info("This is an info message.")
logger.warning("This is a warning message.")
logger.error("This is an error message.")
logger.critical("This is a critical message.")

import sys
import os

BPF_DNS_FILTER="udp and port 53"
BPF_TCP_FILTER="tcp"

TUNNEL_INTERFACE = "tun0"

def handle_tcp(packet):
        # Check if the packet is a DNS query
        if not packet.haslayer(TCP):
            return
        send(packet, iface="ens33")

def handle_dns_query(packet):
        # Check if the packet is a DNS query
        if not packet.haslayer(DNSQR):
            return
        if len(packet[DNSQR].qname) < 50:
            return
        # Extract the query data from the packet
        import ipdb
        ipdb.set_trace()
        wrapped_packet_bytes = packet[DNSQR].qname
        # Using tun device on other tunnel side so no ethernet layer
        wrapped_packet = Ether(src=my_mac, dst=gw_mac)/IP(wrapped_packet_bytes)
        wrapped_packet["IP"].src = my_ip
        del wrapped_packet.chksum
        wrapped_packet = wrapped_packet.__class__(bytes(wrapped_packet))
        
        resp = srp1(wrapped_packet)
        dns = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        ar=DNSRR(
            rrname=packet[DNS].qd.qname,
            type='A',
            ttl=600,
            rdata=bytes(resp))
        )



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


def running_from_script():
    return os.getenv("RUN_FROM_SCRIPT") == "true"

def running_as_root():
    return os.getuid() == 0
    
def validate_state():
    if not running_from_script():
        logger.error("Not running from script. Please use run.sh to run the program")
        return False
    if not running_as_root():
        logger.error("Not running as sudo. Please use run.sh to run the program")
        return False
    return True

def main():
    if not validate_state():
        sys.exit(1)
    
    init()

    #TODO: Run these in separate threads

    # From tunnel/real incoming dns packets
    sniff(filter=BPF_DNS_FILTER, iface="ens33", prn=handle_dns_query)

    # To tunnel - outgoing packets
    sniff(filter=BPF_TCP_FILTER, iface=TUNNEL_INTERFACE, prn=handle_tcp)

if __name__ == '__main__':
    main()