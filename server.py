#!/usr/bin/python3
import ipdb

import logging
import struct

import sys
import os
from fcntl import ioctl

from scapy.config import conf
from scapy.packet import Raw
from scapy.sendrecv import sr, sniff, send, srp1, sendp

from common import *

from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP
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
        logger.info("Starting server initialization")
        self.local_machine = LocalMachine()
        self._descriptor = open("/dev/net/tun", "r+b", buffering=0)
        LINUX_IFF_TUN = 0x0001
        LINUX_IFF_NO_PI = 0x1000
        LINUX_TUNSETIFF = 0x400454CA
        flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
        ifs = struct.pack("16sH22s", b"tun0", flags, b"")
        ioctl(self._descriptor, LINUX_TUNSETIFF, ifs)
        logger.info("Server initialized")

    @classmethod
    def our_dns_packet(cls, packet):
        if not packet[DNSQR].qname.decode().startswith(OUR_DNS_MAGIC) or not packet.haslayer(Raw):
            return False
        return True

    def serve(self):
        logger.info(f"Local machine information: {self.local_machine}")
        logger.info("Starting listening to tunnel packets")
        # From tunnel/real incoming dns packets
        sniff(filter=self.BPF_DNS_FILTER, iface="ens33", prn=self.handle_dns_query)

    def handle_real_dns_packet(self, packet):
        sendp(Ether(dst=self.local_machine.gw_mac)/packet)

    @classmethod
    def extract_wrapped_packet_bytes(cls, packet):
        return bytes(packet[Raw])

    def alter_packet_origin(self, packet):
        wrapped_packet_bytes = self.extract_wrapped_packet_bytes(packet)
        # Using tun device on other tunnel side so no ethernet layer
        wrapped_packet = Ether(src=self.local_machine.my_mac, dst=self.local_machine.gw_mac) / IP(wrapped_packet_bytes)
        wrapped_packet["IP"].src = self.local_machine.my_ip
        for layer in wrapped_packet.layers():
            if not hasattr(wrapped_packet[layer], "chksum"):
                continue
            del wrapped_packet[layer].chksum
        # wrapped_packet = wrapped_packet.__class__(bytes(wrapped_packet))

        return wrapped_packet

    def handle_dns_query(self, packet):
        logger.info("Handling packet")
        # Check if the packet is a DNS query
        if not packet.haslayer(DNSQR):
            logger.info("non dns packet received")
            return
        if not self.our_dns_packet(packet):
            logger.info("real dns packet received")
            self.handle_real_dns_packet(packet)
            return
        logger.info("our dns packet received")
        # Extract the query data from the packet
        altered_packet = self.alter_packet_origin(packet)
        resp = srp1(altered_packet)
        logger.info(resp)
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
            ttl=600
            )
        )
        dns_req = IP(dst=packet[IP].src) / UDP(dport=53) / dns / Raw(bytes(resp[Ether].payload))
        answer = send(dns_req, verbose=1)
        logger.info("Sent data")





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
