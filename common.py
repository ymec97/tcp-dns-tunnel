"""
Module that contains shared utils

The utils are:
    Retrieving the IP and mac addresses of the machin we're running on.
    Retrieving the IP and mac addresses of our gateway.
    Holds the magic we use to identify dns massages between the client and the server.
"""
import os

from scapy.config import conf
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sr


OUR_DNS_MAGIC = "DEADBEEF"

def running_from_script():
    """
    Validates that the client/server was called from within the run.sh script

    Returns:
        bool: whether we are running from the script
    """
    return os.getenv("RUN_FROM_SCRIPT") == "true"


def running_as_root():
    """
    Validates that the client/server has root privileges

    Returns:
        bool: whether we are running as root
    """
    return os.getuid() == 0


def validate_state(logger):
    """
    Validates that both running_as_root and running_from_script are valid

    Returns:
        bool: whether both of them are valid
    """
    if not running_from_script():
        logger.error("Not running from script. Please use run.sh to run the program")
        return False
    if not running_as_root():
        logger.error("Not running as sudo. Please use run.sh to run the program")
        return False
    return True


class LocalMachine:
    def __init__(self):
        conf.verb = 0
        self.my_ip = conf.route.route("0.0.0.0")[1]
        self.my_mac = Ether().src
        self.gw_ip = conf.route.route("0.0.0.0")[2]

        results, unanswered = sr(ARP(op=1, psrc=self.my_ip, pdst=self.gw_ip))
        self.gw_mac = results[0][1].hwsrc

        conf.verb = 1
        self.src_ether = Ether(src=self.my_mac, dst=self.gw_mac)

        self.my_iface = os.popen("ip route get 8.8.8.8 | awk '{print $5}'").read().strip()

    def __str__(self):
        return f"My ip: {self.my_ip}, my mac: {self.my_mac}, gw_ip: {self.gw_ip}, gw_mac: {self.gw_mac}"
