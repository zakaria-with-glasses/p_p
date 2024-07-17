import scapy.all as scapy
from termcolor import cprint
def PING(host) -> bool:

    #the ping request or "ICMP Echo request" is,when a server tries reaching
    #for a specific host to check if the desired server is up;
    #eg: ping google.com

    #in this specific example type = 8 is equivalent to type="echo-request"
    #the padding is just to stop the packet from being caught by the server's firewall.
    
    crafted_packet = scapy.IP(dst=host)/scapy.ICMP(type=8, seq=2)/scapy.padding(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    returned_packet = scapy.sr1(crafted_packet, timeout=3, verbose=0)
    print("Sending ICMP echo request...")
    if returned_packet is not None and returned_packet.haslayer(scapy.ICMP):
        cprint("[x] Null packet returned.", "red")
    
    return False


def SYN_SCAN(host, port) -> bool:
    #the syn scan or "TCP half open scan" is a type of network call;
    #that consists of sending a syn request to the desired host at a specific port
    #if the returned packet is a RESET packet the port is closed;
    #if not (a "SYN-ACK" packet) the port is open;

    crafted_packet = scapy.IP(dst=host)/scapy.TCP(sport=scapy.RandShort(), dport=port, flags="S")
    returned_packet = scapy.sr1(crafted_packet, timeout=3, verbose=0)
    if returned_packet is None:
        return False
    elif returned_packet.haslayer(scapy.TCP):
        if returned_packet.getlayer(scapy.TCP).flags =="SA":
            return True
        elif returned_packet.getlayer(scapy.TCP).flags =="RA":
            return False
        
        return False
    

def FIN_SCAN(host, port) -> bool or str:
    #the fin scan is a scan that allows the atter to determine if the specified port is:
    #either open, closed or filterd.

    crafted_packet = scapy.IP(dst=host)/scapy.TCP(sport=scapy.RandShort(), dport=port, flags="F")
    returned_packet = scapy.sr1(crafted_packet, timeout=3, verbose=0)
    
    if returned_packet is None:
        return True
    elif returned_packet.haslayer(scapy.TCP):
        if returned_packet.getlayer(scapy.TCP).flags == "RA":
            return False
        
        elif (int(returned_packet.getlayer(scapy.ICMP).type)==3 and int(returned_packet.getlayer(scapy.ICMP).code) in [1,2,3,9,10,13]):
            return "filterd"


def XMAS_SCAN(host, port) -> bool or str:
    crafted_packet = scapy.IP(dst=host)/scapy.TCP(sport=scapy.RandShort(), dport=port, flags="FPU")
    returned_packet = scapy.sr1(crafted_packet, timeout=3, verbose=0)

    if returned_packet is None:
        return True
    elif returned_packet.haslayer(scapy.TCP):
        if returned_packet.getlayer(scapy.TCP).flags == "RA":
            return False
        
        elif (int(returned_packet.getlayer(scapy.ICMP).type)==3 and int(returned_packet.getlayer(scapy.ICMP).code) in [1,2,3,9,10,13]):
            return "filterd"