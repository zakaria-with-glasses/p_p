from multiprocessing import Pool
from termcolor import cprint
from .core import FIN_SCAN,XMAS_SCAN,PING,SYN_SCAN
class AirSniffer:
    def __init__(self, args):
        self.args = args
        self.handler(self.args)

    def handler(args):
        #VNamespace(
        #SYN=False, XMAS=True, FIN=False, ping=False, verbosity=None,,
        #ip='10.10.10.10', ports='10,10,20')
        ports_list:list = args.ports.split(",")
        inputs = [(args.ip,)+(int(j),) for j in ports_list]
        with Pool(10) as pool:
            if args.SYN:
                cprint(f"[*] SYN Scanning: {args.ip}", "cyan")
                pool.starmap(SYN_SCAN, inputs)
            if args.XMAS:
                cprint(f"[*] XMAS Scanning: {args.ip}", "cyan")
                pool.starmap(XMAS_SCAN, inputs)
            if args.FIN:
                cprint(f"[*] FIN Scanning {args.ip}", "cyan")
                pool.starmap(FIN_SCAN, inputs)
            if args.ping:
                cprint(f"[*] PING Scanning {args.ip}", "white")
                pool.starmap(PING, args.ip)