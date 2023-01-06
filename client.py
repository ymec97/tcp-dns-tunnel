#!/usr/bin/python3

import logging
import struct
import sys
import os
import time
from fcntl import ioctl
from common import *

from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw
from scapy.sendrecv import sr, send

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

TUNNEL_INTERFACE = b"tun0"
DST_IP = "192.168.150.129"


class TUNInterface:

    def __init__(self):
        self._descriptor = open("/dev/net/tun", "r+b", buffering=0)
        LINUX_IFF_TUN = 0x0001
        LINUX_IFF_NO_PI = 0x1000
        LINUX_TUNSETIFF = 0x400454CA
        flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
        ifs = struct.pack("16sH22s", TUNNEL_INTERFACE, flags, b"")
        ioctl(self._descriptor, LINUX_TUNSETIFF, ifs)

    def read(self, number_bytes: int) -> bytes:
        packet = self._descriptor.read(number_bytes)
        logger.debug('Read %d bytes from %s: %s', len(packet), TUNNEL_INTERFACE, packet)
        return packet

    def write(self, packet: bytes) -> None:
        logger.debug('Writing %s bytes to %s: %s', len(packet), TUNNEL_INTERFACE, packet[:10])
        self._descriptor.write(packet)



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


def tcp_wrapper():
    interface = TUNInterface()
    while time.sleep(0.01) is None:
        buf = interface.read(1500)
        p = IP(buf)
        if not p.haslayer("ICMP"):
            continue

        dns_req = IP(dst=DST_IP) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(OUR_DNS_MAGIC)) / Raw(buf)
        logger.debug(repr(p))
        print(repr(dns_req))
        print(repr(dns_req[DNSQR].qname))
        answer = send(dns_req, verbose=1)

def main():
    if not validate_state():
        sys.exit(1)

    tcp_wrapper()



if __name__ == '__main__':
    main()