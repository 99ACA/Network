import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Disable the annoying No Route found warning !
from scapy.all import *
import ifaddr
from scapy.layers.l2 import Ether,ARP
"""
 Other send functions:
------------------------
sr()        sends and receives without a custom ether() layer
sendp()     sends with a custom ether() layer
srp()       sends and receives at with a custom ether() layer
sr1()       sends packets without custom ether() layer and waits for first answer
sr1p()      sends packets with custom ether() layer and waits for first answer 
"""

def arpPing(subnet=None):
    if(subnet is not None):
        ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet),timeout=2,verbose=0)
        ans.summary()

def netInterfaces():
    adapters = ifaddr.get_adapters()

    for adapter in adapters:
        for ip in adapter.ips:
            if(ip.is_IPv4 == True and ip.ip != "127.0.0.1"): 
                subnet = "{}/{}".format(ip.ip, ip.network_prefix)
                print ("IPs of network adapter {} - {} - subnet {}".format(adapter.nice_name,adapter.name,subnet))
                arpPing(subnet)

if __name__ == '__main__':
    netInterfaces()