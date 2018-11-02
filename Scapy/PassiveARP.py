# import scapy config
from scapy.all import *
from scapy.all import conf as scapyconf
#import scapy.layers.l2
import pprint

from scapy.layers.inet import TCP, Raw, IP
from scapy.layers.l2 import Ether,ARP

def loopEntireInterfaces():
    interfaces = get_windows_if_list()
    #pprint.pprint(interfaces)
    for interface in interfaces:
        pprint.pprint("Network interface name: {}".format(interface["name"]))
        pkts = sniff(filter='arp', count=10,iface=interface["name"],timeout=5)
        pkts.summary()

def print_packet(pkt):   
    ethernet_layer = pkt.getlayer(Ether)
    ip_layer = pkt.getlayer(IP)

    if ip_layer == None:
        if ethernet_layer != None:
            if 'ARP' in pkt:
                print ("Source MAC: {} , Source IP: {} -> Destination IP: {} ?".format(pkt[ARP].hwsrc,pkt[ARP].psrc,pkt[ARP].pdst))
    else:
        print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))

if __name__ == '__main__':
    print("Sniffer on promisc mode: "+ str(scapyconf.sniff_promisc))
    #run on entire interfaces
    pkts = sniff(filter='arp', count=20,timeout=20,prn=print_packet)




