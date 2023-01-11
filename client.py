#!/usr/bin/python3
import base64
import logging
import struct
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor
from fcntl import ioctl

from scapy.sessions import IPSession

from common import *
from scapy.compat import raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import send, sendp, sniff

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
DST_IP = "192.168.2.111"


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
        # logger.debug('Read %d bytes from %s: %s', len(packet), TUNNEL_INTERFACE, packet)
        return packet

    def write(self, packet: bytes) -> None:
        # logger.debug('Writing %s bytes to %s: %s', len(packet), TUNNEL_INTERFACE, repr(packet))
        self._descriptor.write(raw(packet[Ether].payload))


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


def extract_wrapped_packet_bytes(packet):
    return base64.decodebytes(bytes(packet[Raw]))


def alter_packet_dst(packet):

    local_machine = LocalMachine()
    wrapped_packet_bytes = extract_wrapped_packet_bytes(packet)
    # Using tun device on other tunnel side so no ethernet layer
    wrapped_packet = Ether(dst=local_machine.my_mac, src=local_machine.gw_mac) / IP(wrapped_packet_bytes)
    wrapped_packet["IP"].dst = local_machine.my_ip
    for layer in wrapped_packet.layers():
        if not hasattr(wrapped_packet[layer], "chksum"):
            continue
        del wrapped_packet[layer].chksum

    return wrapped_packet


def tcp_wrapper():
    interface = TUNInterface()

    def send_thread():
        while time.sleep(0.01) is None:
            buf = interface.read(1500)
            p = IP(buf)
            if not p[IP].haslayer(TCP):
                continue

            logger.info("Handling outgoing packet")
            dns_req = IP(dst=DST_IP) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=OUR_DNS_MAGIC)) / Raw(base64.encodebytes(buf))
            logger.debug(f"Original packet:\n {repr(p)}\n")
            logger.debug(f"Crafted DNS packet:\n {repr(dns_req)}\n")
            send(dns_req, verbose=False)

    def recv_thread():
        local_machine = LocalMachine()

        def handle_dns_query(packet):
            logger.info("Handling incoming DNS packet")
            # Check if the packet is a DNS query
            if not packet.haslayer(DNSQR):
                logger.info("non dns packet received")
                return
            if not packet[DNSQR].qname.decode().startswith(OUR_DNS_MAGIC) or not packet.haslayer(Raw):
                logger.info("real dns packet received")
                sendp(Ether(dst=local_machine.gw_mac) / packet, verbose=False)
                return

            # Extract the query data from the packet
            new_packet = alter_packet_dst(packet)
            logger.debug(f"Answer packet:\n {repr(new_packet)}\n")
            interface.write(new_packet)

        sniff(session=IPSession, filter=f"ip and src not {local_machine.my_ip}", prn=handle_dns_query)

    with ThreadPoolExecutor(max_workers=10, thread_name_prefix='tun-') as pool:
        pool.submit(send_thread)
        pool.submit(recv_thread)


def main():
    if not validate_state():
        sys.exit(1)

    tcp_wrapper()


if __name__ == '__main__':
    main()
