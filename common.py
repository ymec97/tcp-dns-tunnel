from scapy.config import conf
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sr


OUR_DNS_MAGIC = "DEADBEEF"


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

    def __str__(self):
        return f"My ip: {self.my_ip}, my mac: {self.my_mac}, gw_ip: {self.gw_ip}, gw_mac: {self.gw_mac}"
