#!/usr/bin/python3
"""
Module for the client side of the tunnel

This module runs 2 threads:
    * send_thread - This thread is listening on the tun0 interface.
                    for every packet it reads from the interface the thread create dns query packet, concatenate
                    the packet it read with the dns packet and send the dns packet to the server.
    * recv_thread - This thread is listening on the interface that has access to the network.
                    for every packet that it reads that came from the server the thread extract from it the actual
                    answer and write it back to the tun interface.
"""
import base64
import logging
import struct
import sys
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
logger.setLevel(logging.INFO)

# create a console handler and set the log level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# create a formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add the formatter to the console handler
ch.setFormatter(formatter)

# add the console handler to the logger
logger.addHandler(ch)

TUNNEL_INTERFACE = b"tun0"


class TUNInterface:
    """
    Class that encapsulate the access for the tun interface

    Attributes:
        _descriptor (IO): The file descriptor for the interface
    """

    def __init__(self):
        """
        The constractor for the class.

        Opens the file descriptor of the tun0 interface
        """
        self._descriptor = open("/dev/net/tun", "r+b", buffering=0)
        LINUX_IFF_TUN = 0x0001
        LINUX_IFF_NO_PI = 0x1000
        LINUX_TUNSETIFF = 0x400454CA
        flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
        ifs = struct.pack("16sH22s", TUNNEL_INTERFACE, flags, b"")
        ioctl(self._descriptor, LINUX_TUNSETIFF, ifs)

    def read(self, number_bytes: int) -> bytes:
        """
        Reads number_bytes from the tun interface

        Args:
            number_bytes: number of bytes to read

        Returns:
            bytes: bytes we read
        """
        packet = self._descriptor.read(number_bytes)
        return packet

    def write(self, packet: bytes) -> None:
        """
        Writes packet back to the tun interface

        Args:
            packet (bytes): packet in bytes representation
        """
        self._descriptor.write(raw(packet[Ether].payload))


def extract_wrapped_packet_bytes(packet):
    """
    Extract the actual data from the dns packet

    Args:
        packet: the dns packet we use as tunnel

    Returns:
        the actual bytes of the tcp packet
    """
    return base64.decodebytes(bytes(packet[Raw]))


def alter_packet_dst(packet):
    """
    Change the packet dst addresses (mac and ip)

    This function is used on the recv_thread, the answers that we get from the server are with the server as
    the destination, so in order for the applications that run on the client host to accept the answers we need
    to change the destination to be ourselves.

    Args:
        packet: the dns packet that contains the answer

    Returns:
        packet: the answer after changing the dst to be ourselves
    """
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


def tcp_wrapper(server_ip):
    """
    the client side tunnel

    Runs the send_thread and recv_thread that responsible for wrapping the outgoing tcp traffic with dns packet
    and extract the answers from the incoming dns packets.
    """
    interface = TUNInterface()

    def send_thread():
        """
        Listen on the tun interface and send every packet wrapped with dns packet
        """
        while time.sleep(0.01) is None:
            buf = interface.read(1500)
            p = IP(buf)
            if not p[IP].haslayer(TCP):
                continue

            logger.info("Handling outgoing packet")
            dns_req = IP(dst=server_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=OUR_DNS_MAGIC)) / Raw(base64.encodebytes(buf))
            logger.debug(f"Original packet:\n {repr(p)}\n")
            logger.debug(f"Crafted DNS packet:\n {repr(dns_req)}\n")
            send(dns_req, verbose=False)

    def recv_thread():
        """

        Listen on the main interface and every packet that came from the server is extract the answer and
        change the dst addresses and writes it back to the tun interface.
        """
        local_machine = LocalMachine()

        def handle_dns_query(packet):
            """
            Make sure the packet is from the server and handel it accordingly.
            Args:
                packet: Incoming packet
            """
            logger.info("Handling incoming DNS packet")
            # Check if the packet is a DNS query
            if not packet.haslayer(DNSQR):
                logger.debug("non dns packet received")
                return
            if not packet[DNSQR].qname.decode().startswith(OUR_DNS_MAGIC) or not packet.haslayer(Raw):
                logger.debug("real dns packet received")
                sendp(Ether(dst=local_machine.gw_mac) / packet, verbose=False)
                return

            # Extract the query data from the packet
            new_packet = alter_packet_dst(packet)
            logger.debug(f"Answer packet:\n {repr(new_packet)}\n")
            interface.write(new_packet)

        sniff(session=IPSession, filter=f"ip and src not {local_machine.my_ip}", prn=handle_dns_query)


    with ThreadPoolExecutor(max_workers=10, thread_name_prefix='tun-') as pool:
        pool.submit(recv_thread)
        pool.submit(send_thread)


def main():
    """
    Main entry point of the client side tunnel.
    """
    client_arg_count = 2
    server_ip_arg_index = 1
    if len(sys.argv) != client_arg_count:
        logger.error(f"Expected {client_arg_count} arguments, got {len(sys.argv)}")
        sys.exit(1)
    if not validate_state(logger):
        sys.exit(1)

    tcp_wrapper(sys.argv[server_ip_arg_index])


if __name__ == '__main__':
    main()
