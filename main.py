#!/bin/python3
import lib
import argparse

def index():
    parser = argparse.ArgumentParser(description="A general use network navigator.", prog="pyr4m1d")
    ### PORT SCANNING FLAGS ###
    
    
    parser.add_argument("-pS","--SYN",action="store_true" ,help="flag may be used in case of SYN Steath port scanning.\nSeperate wanted ports using a comma.\nExample: pyr4m1d.py -pS 80,443." )
    parser.add_argument("-pX", "--XMAS",action="store_true")
    parser.add_argument("-pF", "--FIN",action="store_true")
    parser.add_argument("-Pn", '--ping', action="store_true")
    
    parser.add_argument("-v", "--verbosity" ,type=int, choices=[0,1,2], help="This flag determines how much output will be shown to the end user ;)")
    parser.add_argument("-PL", "--pool_length", type=int, default=5)
    parser.add_argument("ip", help="You shall input a target ip.")
    parser.add_argument("ports", help="You shall input ports or we'll use the first 1000 known ports")
    ARGS =parser.parse_args()
    
    lib.AirSniffer.handler(ARGS)
    

def banner():
    print(
"""
 ██████╗ ██╗   ██╗██████╗ ██╗  ██╗███╗   ███╗ ██╗██████╗ 
 ██╔══██╗╚██╗ ██╔╝██╔══██╗██║  ██║████╗ ████║███║██╔══██╗
 ██████╔╝ ╚████╔╝ ██████╔╝███████║██╔████╔██║╚██║██║  ██║
 ██╔═══╝   ╚██╔╝  ██╔══██╗╚════██║██║╚██╔╝██║ ██║██║  ██║
 ██║        ██║   ██║  ██║     ██║██║ ╚═╝ ██║ ██║██████╔╝
 ╚═╝        ╚═╝   ╚═╝  ╚═╝     ╚═╝╚═╝     ╚═╝ ╚═╝╚═════╝ 

 
-------------------------- Made by c1ph3r --------------------------
"""
    )
if __name__ == "__main__":
    banner()
    index()