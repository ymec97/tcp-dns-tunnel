#!/usr/bin/python3

import logging

import sys
import os

from scapy.config import conf
from scapy.sendrecv import sr, sniff, send

from common import *

from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

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


class TunnelServer:
    BPF_DNS_FILTER = "udp and port 53"
    TUNNEL_INTERFACE = "tun0"

    def __init__(self):
        self.local_machine = LocalMachine()
        logger.info("server initialized")

    @classmethod
    def our_dns_packet(cls, packet):
        if packet[DNSQR].qname != OUR_DNS_MAGIC:
            return

    def serve(self):
        logger.info(f"Local machine information: {self.local_machine}")
        logger.info("Starting listening to tunnel packets")
        # From tunnel/real incoming dns packets
        sniff(filter=self.BPF_DNS_FILTER, iface=self.TUNNEL_INTERFACE, prn=self.handle_dns_query)

    @classmethod
    def handle_real_dns_packet(cls, packet):
        send(packet)

    def handle_dns_query(self, packet):
        # Check if the packet is a DNS query
        if not packet.haslayer(DNSQR):
            return
        if not self.our_dns_packet(packet):
            self.handle_real_dns_packet(packet)
            return
        # Extract the query data from the packet
        import ipdb
        ipdb.set_trace()
        wrapped_packet_bytes = packet[DNSQR].qname
        # Using tun device on other tunnel side so no ethernet layer
        wrapped_packet = Ether(src=self.local_machine.my_mac, dst=self.local_machine.gw_mac)/IP(wrapped_packet_bytes)
        wrapped_packet["IP"].src = self.local_machine.my_ip
        del wrapped_packet.chksum
        wrapped_packet = wrapped_packet.__class__(bytes(wrapped_packet))
        #
        # resp = srp1(wrapped_packet)
        # dns = DNS(
        # id=packet[DNS].id,
        # qd=packet[DNS].qd,
        # aa=1,
        # rd=0,
        # qr=1,
        # qdcount=1,
        # ancount=1,
        # nscount=0,
        # arcount=0,
        # ar=DNSRR(
        #     rrname=packet[DNS].qd.qname,
        #     type='A',
        #     ttl=600,
        #     rdata=bytes(resp))
        # )


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
    server = TunnelServer()
    server.serve()


if __name__ == '__main__':
    main()
