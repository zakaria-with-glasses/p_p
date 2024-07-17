import scapy.all as scapy
class NetworkNavigator():
    def __init__(self, host:str, op:str, range:str):
        super(NetworkNavigator, self).__init__()
        self.daemon = True
        self.host = host
        self.operation = op
        self.range = self.range_parser(range)

        self.run()

    def range_parser(self, rng:str) -> range or list(int):
       if "-" in rng:
            (start, end) = rng.split("-")
            return range(int(start, 10), int(end, 10)+1)
       else:
            return list(map(int,rng.split(",")))
    
    def host_ckeck(self) -> bool:
        
        pkt = scapy.IP(dst=self.host)/scapy.ICMP(type=8, seq=2)/scapy.Padding(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        res = scapy.sr1(pkt, timeout=3, verbose=0)
        if res is not None and res.haslayer(scapy.ICMP):
            return True
        return False
    

    def SYN_enum(self) -> dict:
        print("[+] starting syn scan...")
        ports_stat = {}
        for port in self.range:
            print(f"port: {port}")
            pkt = scapy.IP(dst=self.host)/scapy.TCP(sport=scapy.RandShort(), dport=port,flags="S")
            res = scapy.sr1(pkt, timeout=3, verbose=0)
            if res is None:
                ports_stat[str(port)] = 0

            elif res.haslayer(scapy.TCP):
                if res.getlayer(scapy.TCP).flags == "SA":
                    ports_stat[str(port)] = 1
                
                elif res.getlayer(scapy.TCP).flags == "RA":
                    ports_stat[str(port)] = 0
        print(ports_stat)
        return ports_stat
    
    def FIN_enum(self)-> dict:
        
        port_results = {}
        for port in self.range:
            pkt = scapy.IP(dst=self.host)/scapy.TCP(sport=scapy.RandShort(), dport=port, flags="F")
            res = scapy.sr1(pkt, timeout=3, verbose=0)
            if res is None:
                port_results[str(port)] = 1
            elif res.haslayer(scapy.TCP):
                if res.getlayer(scapy.TCP).flags == "RA":
                    port_results[str(port)] = 0
                if (int(res.getlayer(scapy.ICMP).type)==3 and int(res.getlayer(scapy.ICMP).code) in [1,2,3,9,10,13]):
                    port_results[str(port)] = 2

        return port_results
    
    def XMAS_enum(self) -> dict:
        
        port_results = {}
        for port in self.range:
            pkt = scapy.IP(dst=self.host)/scapy.TCP(sport=scapy.RandShort(), dport=port, flags="FPU")
            res = scapy.sr1(pkt, timeout=3, verbose=0)
            if res is None:
                port_results[str(port)]  = 1
            elif res.haslayer(scapy.TCP):
                if res.getlayer(scapy.TCP).flags == 0x14:
                    port_results[str(port)] = 0
                elif (int(res.getlayer(scapy.ICMP).type)==3 and int(res.getlayer(scapy.ICMP).code) in [1,2,3,9,10,13]):
                    port_results[str(port)] = 2



    def run(self):
        if self.operation == "SYN":
            self.SYN_enum()
        elif self.operation == "XMAS":
            self.XMAS_enum()
        elif self.operation == "FIN":
            self.FIN_enum()
        elif self.operation == "ping":
            self.host_ckeck()
        else:
            print("[x] Operation not supported")
    