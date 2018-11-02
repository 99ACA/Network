#https://scapy.readthedocs.io/en/latest/introduction.html
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Disable the annoying No Route found warning !
from scapy.all import *
from scapy.layers.inet import TCP, Raw, IP, ICMP
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

"""
URG     ACK     PSH     RST     SYN     FIN
32      16      8       4       2       1
--      X       --      --      X       --
"""
SYN_ACK=0x18




def is_up(ip):
    """ Tests if host is up """
    #return True
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=0.5)

    if resp == None:
        #return False
        return True
    else:
        return True

def reset_half_open(ip, ports):
    # Reset the connection to stop half-open connections from pooling up
    sr(IP(dst=ip)/TCP(dport=ports, flags='AR'), timeout=1)

def is_open(ip, ports, timeout=0.2):
    results = {port:None for port in ports}
    to_reset = []
    p = IP(dst=ip)/TCP(dport=ports, flags='S')  # Forging SYN packet
    answers, un_answered = sr(p, timeout=timeout)  # Send the packets
    for req, resp in answers:
        if not resp.haslayer(TCP):
            continue
        tcp_layer = resp.getlayer(TCP)
        print("TCP Flag "+ str(tcp_layer.flags))
        if tcp_layer.flags == 'SA': # SYN & ACK
            to_reset.append(tcp_layer.sport)
            results[tcp_layer.sport] = True
        elif tcp_layer.flags == 0x14:
            results[tcp_layer.sport] = False

    # Bulk reset ports
    reset_half_open(ip, to_reset)
    return results

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def arpPing():
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="10.0.0.0/24"),timeout=2)
    ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%"))

def portScan(ip = "54.210.208.21"):
    conf.verb = 0 # Disable verbose in sr(), sr1() methods
    start_time = time.time()
    if is_up(ip):
        print ("Host %s is up, start scanning" % ip)
        for ports in chunks(range(1, 1024), 100):
            print ("Scan port : {}".format(ports))
            results = is_open(ip, ports)
            for p, r in results.items():
                if r != None:
                    print (p, ':', r)
        duration = time.time()-start_time
        print ("%s Scan Completed in %fs" % (ip, duration))
    else:
        print("Host %s is Down" % ip)

if __name__ == '__main__':
    #portScan()
    arpPing()

    