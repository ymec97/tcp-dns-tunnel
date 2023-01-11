#!/usr/bin/python3
import base64
import copy

import ipdb

import logging
import struct

import sys
import os
from fcntl import ioctl

from scapy.packet import Raw
from scapy.sendrecv import sniff, send, sendp

from common import *

from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether


log_level = logging.DEBUG
logger = logging.getLogger(__name__)
# set the log level to debug
logger.setLevel(log_level)

# create a console handler and set the log level to debug
ch = logging.StreamHandler()
ch.setLevel(log_level)

# create a formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add the formatter to the console handler
ch.setFormatter(formatter)

# add the console handler to the logger
logger.addHandler(ch)


from concurrent.futures import ThreadPoolExecutor

VERBOSE=0
class TunnelServer:
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
        self.dns_bpf_filter = f"udp and port 53 and src not {self.local_machine.my_ip}"
        self.tcp_bpf_filter = f"tcp and src not {self.local_machine.my_ip}"
        self.active_session_mapping = {}
        logger.info("Server initialized")
        logger.info(f"Listening to: {self.dns_bpf_filter}")


    @classmethod
    def our_dns_packet(cls, packet):
        if not packet[DNSQR].qname.decode().startswith(OUR_DNS_MAGIC) or not packet.haslayer(Raw):
            return False
        return True

    def is_for_active_session(self, packet):
        if packet[TCP].dport in self.active_session_mapping.keys():
            return True
        return False

    def tunnel_response_tcp_packet(self, packet):
        if not packet.haslayer(TCP) or not self.is_for_active_session(packet):
            return False
        return True

    def _listen_dns(self):
        """ From tunnel/real incoming dns packets """
        logger.info("Starting listening to tunnel dns packets")
        sniff(filter=self.dns_bpf_filter, iface="ens33", prn=self.handle_dns_query)

    def _listen_tcp(self):
        logger.info("Starting listening to tcp response packets")
        """ From tunnel/real incoming dns packets """
        sniff(filter=self.tcp_bpf_filter, iface="ens33", prn=self.handle_tcp_response)


    def serve(self):
        logger.info(f"Local machine information: {self.local_machine}")
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.submit(self._listen_dns)
            executor.submit(self._listen_tcp)

    @classmethod
    def extract_wrapped_packet_bytes(cls, packet):
        return base64.decodebytes(bytes(packet[Raw]))

    def alter_packet_origin(self, packet):
        wrapped_packet_bytes = self.extract_wrapped_packet_bytes(packet)
        # Using tun device on other tunnel side so no ethernet layer
        wrapped_packet = Ether(src=self.local_machine.my_mac, dst=self.local_machine.gw_mac) / IP(wrapped_packet_bytes)
        wrapped_packet[IP].src = self.local_machine.my_ip
        for layer in wrapped_packet.layers():
            if not hasattr(wrapped_packet[layer], "chksum"):
                continue
            del wrapped_packet[layer].chksum
        # wrapped_packet = wrapped_packet.__class__(bytes(wrapped_packet))

        return wrapped_packet

    def handle_real_packet_to_server(self, packet):
        sendp(Ether(dst=self.local_machine.gw_mac)/packet, verbose=VERBOSE)

    def get_resp_data_from_active_sessions(self, packet):
        return self.active_session_mapping[packet[TCP].dport]

    def handle_tcp_response(self, packet):
        logger.info("Handling tcp response packet")
        if not self.tunnel_response_tcp_packet(packet):
            logger.info("non tunnel tcp response packet received")
            self.handle_real_packet_to_server(packet)
            return
        try:
            logger.info("tunnel response tcp packet received")
            resp_bytes = base64.encodebytes(bytes(packet[Ether].payload))
            resp_data = copy.deepcopy(self.get_resp_data_from_active_sessions(packet))
            dns = resp_data[DNS]
            resp_data.remove_payload()
            ip = resp_data[IP]
            dns_req = IP(dst=ip[IP].src) / UDP(dport=53) / dns / Raw(resp_bytes)
            logger.info(f"Sending response dns packet from {packet[IP].src}, length is: {len(dns_req)}")
            send(dns_req, verbose=VERBOSE)
            logger.info(f"Sent dns response packet from {packet[IP].src}")
        except:
            ipdb.post_mortem()

    def add_packet_to_active_session(self, dns_packet, tcp_packet):
        src_port = tcp_packet[TCP].sport
        if src_port in self.active_session_mapping.keys():
            # logger.error(f"Session for sport {src_port} already exists")
            # return False
            return True

        resp_data = IP(src=dns_packet[IP].src)/DNS(
            id=dns_packet[DNS].id,
            qd=dns_packet[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            ar=DNSRR(
                rrname=dns_packet[DNS].qd.qname,
                type='A',
                ttl=600
            )
        )
        self.active_session_mapping[src_port] = resp_data
        return True

    def handle_dns_query(self, dns_packet):
        logger.info("Handling dns_packet")
        # Check if the dns_packet is a DNS query
        if not dns_packet.haslayer(DNSQR):
            logger.info("non dns dns_packet received")
            return
        if not self.our_dns_packet(dns_packet):
            logger.info("real dns dns_packet received")
            self.handle_real_packet_to_server(dns_packet)
            return
        logger.info("our dns dns_packet received")
        # Extract the query data from the dns_packet
        tcp_packet = self.alter_packet_origin(dns_packet)
        logger.info(f"Sending altered dns_packet to: {tcp_packet[IP].dst}")
        sendp(tcp_packet, verbose=VERBOSE)
        logger.info(f"Altered dns_packet SENT: {tcp_packet[IP].dst}")
        if not self.add_packet_to_active_session(dns_packet, tcp_packet):
            logger.error(f"Failed creating active session for packet from sport {tcp_packet[TCP].sport} - not listening for replies")








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
