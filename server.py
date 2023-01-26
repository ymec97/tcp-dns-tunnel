#!/usr/bin/python3
"""
Module for the server side of the tunnel

This module runs 2 threads:
    * listen_dns - This thread is listening on the for incoming dns packets.
                    For every dns packet that is part of the tunnel extract the tcp packet alter it so the server
                    will get the response (change the src addresses) and send the altered packet.
    * listen_tcp - This thread is listening for incoming tcp packets, if the packet is part of an active client session
                    wrapp the tcp with dns response and send it back to the client.
"""
import base64
import copy
import threading
import logging
from concurrent.futures import ThreadPoolExecutor
import sys

from common import *

from scapy.packet import Raw
from scapy.sendrecv import sniff, send, sendp
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether

from concurrent.futures import ThreadPoolExecutor

log_level = logging.INFO
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

VERBOSE = 0


class TunnelServer:
    """
    Class that encapsulate the server side tunnel


    Attributes:
        source_client:
        local_machine:
        dns_bpf_filter: filter that used inorder to catch only dns packet that the server is the destination
        tcp_bpf_filter: filter that used inorder to catch tcp packets that the server is the destination
        active_session_mapping:
    """

    def __init__(self):
        """
        The constractor for the class.

        Initialize all the attributes for proper running of the tunnel server
        """
        self.source_client = ""
        logger.info("Starting server initialization")
        self.local_machine = LocalMachine()
        self.dns_bpf_filter = f"udp and port 53 and src not {self.local_machine.my_ip}"
        self.tcp_bpf_filter = f"tcp and dst {self.local_machine.my_ip}"
        self.active_session_mapping = []
        logger.info("Server initialized")
        logger.info(f"Listening to: {self.dns_bpf_filter}")

    @classmethod
    def our_dns_packet(cls, packet):
        """
        Make sure the dns packet is from the client

        Parameters:
            packet: Incoming dns packet

        Returns:
            bool: whether the packet is from the client
        """
        if not packet[DNSQR].qname.decode().startswith(OUR_DNS_MAGIC) or not packet.haslayer(Raw):
            return False
        return True

    def is_for_active_session(self, packet):
        """
        Make sure the tcp packet is part of an active client session

        Parameters:
            packet: Incoming tcp packet

        Returns:
            bool: whether the packet is part of active session
        """
        if packet[TCP].dport in self.active_session_mapping:
            return True
        return False

    def tunnel_response_tcp_packet(self, packet):
        """
        Make sure the packet is tcp packet and is part of an active client session

        Parameters:
           packet: Incoming packet

        Returns:
           bool: whether the packet is tcp and part of active session
        """
        if not packet.haslayer(TCP) or not self.is_for_active_session(packet):
            return False
        return True

    def _listen_dns(self):
        """
        Listen for incoming dns packets

        For every incoming dns packet calls handle_dns_query
        """
        """ From tunnel/real incoming dns packets """
        logger.info("Starting listening to tunnel dns packets")
        sniff(filter=self.dns_bpf_filter, iface=self.local_machine.my_iface, prn=self.handle_dns_query)

    def _listen_tcp(self):
        """
        Listen for incoming tcp packets

        For every incoming tcp packet calls handle_tcp_response
        which sends the response to the client side of the tunnel
        """
        logger.info("Starting listening to tcp response packets")
        """ From tunnel/real incoming dns packets """
        sniff(filter=self.tcp_bpf_filter, iface=self.local_machine.my_iface, prn=self.handle_tcp_response)

    def serve(self):
        """
        The server side tunnel

        Runs _listen_dns and _listen_tcp as threads.
        """
        logger.info(f"Local machine information: {self.local_machine}")
        logger.critical(f"Active threads: {threading.active_count()}")
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.submit(self._listen_dns)
            executor.submit(self._listen_tcp)

    @classmethod
    def extract_wrapped_packet_bytes(cls, packet):
        """
        Extract the actual data from the dns packet

        Args:
            packet: the dns packet we use as tunnel

        Returns:
            the actual bytes of the tcp packet
        """
        return base64.decodebytes(bytes(packet[Raw]))

    def alter_packet_origin(self, packet):
        """
        Change the packet src addresses (mac and ip)

        This function is used when incoming dns packet is handled.
        Inorder to properly send the client tcp packet we need to change the src ip and mac to be our, and update the
        checksum accordingly.

        Args:
            packet: the dns packet that contains the tcp packet

        Returns:
            packet: the tcp packet that is ready to sent
        """
        wrapped_packet_bytes = self.extract_wrapped_packet_bytes(packet)
        # Using tun device on other tunnel side so no ethernet layer
        wrapped_packet = Ether(src=self.local_machine.my_mac, dst=self.local_machine.gw_mac) / IP(wrapped_packet_bytes)
        wrapped_packet[IP].src = self.local_machine.my_ip
        for layer in wrapped_packet.layers():
            if not hasattr(wrapped_packet[layer], "chksum"):
                continue
            del wrapped_packet[layer].chksum

        return wrapped_packet

    def handle_real_packet_to_server(self, packet):
        """
        Send real dns packets (not tunnel ones) to the system to handle.

        Inorder to prevent automatic response on tunnel related dns requests all the incoming dns packets are
        transferred to the localhost. If we get real dns request (and not one from the tunnel) pass it back to the
        system to handle.

        Args:
              packet: Incoming dns packet
        """
        sendp(Ether(dst=self.local_machine.my_mac) / packet, verbose=VERBOSE)

    def get_resp_data_from_active_sessions(self):
        """
        Get packet data for a response packet with the tunnel's client information.

        In the future will be client specific for multy client support
        """

        return IP(src=self.source_client) / DNS(
            id=0,
            qd=DNSQR(qname=OUR_DNS_MAGIC_DOMAIN_PREFIX),
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            ar=DNSRR(
                rrname=OUR_DNS_MAGIC_DOMAIN_PREFIX.encode(),
                type='A',
                ttl=600
            )
        )

    def handle_tcp_response(self, packet):
        """
        Send tcp response back to the client.

        For every tcp packet only handle it if it is part of an active client session.
        If the tcp is part of an active session then create DNS response packet tht encapsulates the tcp response
        and send ot to the appropriate client.

        Args:
            packet: Incoming tcp packet
        """
        logger.debug("Handling tcp response packet")
        if not self.tunnel_response_tcp_packet(packet):
            logger.debug("non tunnel tcp response packet received")
            return
        logger.debug("tunnel response tcp packet received")
        resp_bytes = base64.encodebytes(bytes(packet[Ether].payload))
        resp_data = copy.deepcopy(self.get_resp_data_from_active_sessions())
        dns = resp_data[DNS]
        resp_data.remove_payload()
        ip = resp_data[IP]
        dns_req = IP(dst=ip[IP].src) / UDP(dport=53) / dns / Raw(resp_bytes)
        logger.debug(f"Sending response dns packet from {packet[IP].src}, length is: {len(dns_req)}")
        send(dns_req, verbose=VERBOSE)
        logger.debug(f"Sent dns response packet from {packet[IP].src}")

    def add_packet_to_active_session(self, tcp_packet):
        """
            Save the source port to identify tcp responses that are destined to the tunnel by their dest port

            When a packet is returned from a target server, we check if the destination port is for
            an active session, if so it's for the client side of the tunnel,
            otherwise it's for the dns tunnel server itself
        """
        src_port = tcp_packet[TCP].sport
        if src_port not in self.active_session_mapping:
            self.active_session_mapping.append(src_port)

    def handle_dns_query(self, dns_packet):
        """
        Send tcp packet from the client to the wanted destination.

        For every dns packet only handle it if it is part of the tunnel (has the tunnel magic)
        If the packet is part of the tunnel extract from it the actual tcp packet, alter the packet to it looked as if
        the server is the one sending it.

        Args:
            dns_packet: Incoming tcp packet
        """
        logger.debug("Handling dns_packet")
        # Check if the dns_packet is a DNS query
        if not dns_packet.haslayer(DNSQR):
            logger.debug("non dns dns_packet received")
            return
        if not self.our_dns_packet(dns_packet):
            logger.debug("real dns dns_packet received")
            self.handle_real_packet_to_server(dns_packet)
            return
        logger.debug("our dns dns_packet received")
        if self.source_client == "":
            logger.debug("Client connected for the first time - saving source ip")
            self.source_client = dns_packet[IP].src
        # Extract the query data from the dns_packet
        tcp_packet = self.alter_packet_origin(dns_packet)
        logger.debug(f"Sending altered tcp packet to: {tcp_packet[IP].dst}")
        sendp(tcp_packet, verbose=VERBOSE)
        logger.debug(f"Altered tcp packet SENT: {tcp_packet[IP].dst}")
        self.add_packet_to_active_session(tcp_packet)


def main():
    """
    Main entry point of the server side tunnel.
    """
    if not validate_state(logger):
        sys.exit(1)
    server = TunnelServer()
    server.serve()


if __name__ == '__main__':
    main()
