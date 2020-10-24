#!/usr/bin/env python3

# -*- coding:utf-8 -*-
import os,sys,socket,ipaddress,argparse,textwrap,logging
from scapy.all import *
from ctypes import *
from time import sleep
from threading import Thread
from modules import service_detection,os_detection
from progress.bar import ChargingBar
from colorama import Fore
import rpycolors

old_print = print
print = rpycolors.Console().print

white   = Fore.WHITE
black   = Fore.BLACK
red     = Fore.RED
reset   = Fore.RESET
blue    = Fore.BLUE
cyan    = Fore.CYAN
yellow  = Fore.YELLOW
green   = Fore.GREEN
magenta = Fore.MAGENTA

OPEN_PORT = 80

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


clear = lambda:os.system('cls' if os.name == 'nt' else 'clear')

__version__ = "v1.1.3"

def print_figlet(sleep=True):
    clear()
    print(textwrap.dedent(
    f'''
    .d8b.  .d8888. d888888b .d8888. db    db 
    d8' `8b 88'  YP `~~88~~' 88'  YP 88    88 
    88ooo88 `8bo.      88    `8bo.   88    88 
    88~~~88   `Y8b.    88      `Y8b. 88    88 
    88   88 db   8D    88    db   8D 88b  d88 
    YP   YP `8888Y'    YP    `8888Y' ~Y8888P'

    Github: https://github.com/ReddyyZ/astsu
    By: ReddyyZ
    Version: {__version__}

    [[cyan]*[/cyan]]Starting...
    '''
    ))

    if sleep:
        try:
            time.sleep(4.5)
        except KeyboardInterrupt:
            pass

class Scanner:
    def __init__(self,target=None,my_ip=None,protocol=None,timeout=5,interface=None):
        self.target = target
        self.my_ip = my_ip
        self.protocol = protocol
        self.timeout = timeout
        self.interface = interface

    def port_scan(self,stealth=None,port=80):
        protocol = self.protocol if self.protocol else "TCP"

        if stealth:
            pkt = IP(dst=self.target)/TCP(dport=port,flags="S")
            scan = sr1(pkt,timeout=self.timeout,verbose=0)

            if scan == None:
                return {port: 'Filtered'}

            elif scan.haslayer(TCP):
                if scan.getlayer(TCP).flags == 0x12: # 0x12 SYN+ACk
                    pkt = IP(dst=self.target)/TCP(dport=port,flags="R")
                    send_rst = sr(pkt,timeout=self.timeout,verbose=0)

                    return {port: 'Open'}
                elif scan.getlayer(TCP).flags == 0x14:
                    return {port: 'Closed'}
            elif scan.haslayer(ICMP):
                if int(scan.getlayer(ICMP).type) == 3 and int(scan.getlayer(ICMP).code in [1,2,3,9,10,13]):
                    return {port: 'Filtered'}

        else:
            if protocol == "TCP":
                pkt = IP(dst=self.target)/TCP(dport=port,flags="S")
                scan = sr1(pkt,timeout=self.timeout,verbose=0)

                if scan == None:
                    return {port: 'Filtered'}

                elif scan.haslayer(TCP):
                    if scan.getlayer(TCP).flags == 0x12: # 0x12 SYN+ACk
                        pkt = IP(dst=self.target)/TCP(dport=port,flags="AR")
                        send_rst = sr(pkt,timeout=self.timeout,verbose=0)

                        return {port: 'Open'}
                    elif scan.getlayer(TCP).flags == 0x14:
                        return {port: 'Closed'}

            elif protocol == "UDP":
                pkt = IP(dst=self.target)/UDP(dport=port)
                scan = sr1(pkt, timeout=self.timeout,verbose=0)

                if scan == None:
                    return {port: 'Open/Filtered'}
                elif scan.haslayer(UDP):
                    return {port: 'Closed'}
                elif scan.haslayer(ICMP):
                    if int(scan.getlayer(ICMP).type) == 3 and int(scan.getlayer(ICMP).code) == 3:
                        return {port: 'Closed'}
                    elif int(scan.getlayer(ICMP).type) == 3 and int(scan.getlayer(ICMP).code) in [1,2,9,10,13]:
                        return {port: 'Closed'}

    def handle_port_response(self,ports_saved,response,port):
        """

        Handle the port_scan response

        ports_saved : Dict with the variables where's located the open ports, filtered ports, open or filtered.
        response : the response of port_scan function
        port : port of the scan

        """

        open_ports = ports_saved['open']
        filtered_ports = ports_saved['filtered']
        open_or_filtered = ports_saved['open/filtered']

        if response[port] == "Closed":
            logging.warning(f"Port: {port} - Closed")
        elif response[port] == "Open":
            logging.info(f"Port: {port} - Open")
            open_ports.append(port)
        elif response[port] == "Filtered":
            logging.warning(f"Port: {port} - Filtered")
            filtered_ports.append(port)
        elif response[port] == "Open/Filtered":
            logging.info(f"Port: {port} - Open/Filtered")
            open_or_filtered.append(port)
        else:
            pass

        return (
            open_ports,
            filtered_ports,
            open_or_filtered
        )

    def common_scan(self,stealth=None,sv=None):
        # print_figlet()

        if not self.protocol:
            protocol = "TCP"
        else:
            protocol = self.protocol

        ports = [21,22,80,443,3306,14147,2121,8080,8000]
        open_ports = []
        filtered_ports = []
        open_or_filtered = []

        if stealth:
            logging.info("Starting - Stealth TCP Port Scan\n")
        else:
            if protocol == "TCP":
                logging.info("Starting - TCP Connect Port Scan\n")
            elif protocol == "UDP":
                logging.info("Starting - UDP Port Scan\n")
            else:
                pass

        for port in ports:
            
            scan = self.port_scan(port=port,stealth=stealth)
        
            if scan:
                ports_saved = {
                    "open": open_ports,
                    "filtered": filtered_ports,
                    "open/filtered": open_or_filtered
                }

                open_ports, filtered_ports, open_or_filtered = self.handle_port_response(ports_saved=ports_saved,response=scan,port=port)

        if open_ports or filtered_ports or open_or_filtered:
            total = len(open_ports) + len(filtered_ports) + len(open_or_filtered)

            print("")
            logging.info(f"Founded {total} ports!")

            for port in open_ports:
                logging.info(f"Port: {port} - Open")
            for port in filtered_ports:
                logging.warning(f"Port: {port} - Filtered")
            for port in open_or_filtered:
                logging.info(f"Port: {port} - Open/Filtered")

    def range_scan(self,start,end=None,stealth=None,sv=None):
        open_ports = []
        filtered_ports = []
        open_or_filtered = []
        protocol = self.protocol

        if not protocol:
            protocol = "TCP"

        # print_figlet()
        if protocol == "TCP" and stealth:
            logging.info("Starting - TCP Stealth Port Scan\n")
        elif protocol == "TCP" and not stealth:
            logging.info("Starting - TCP Connect Port Scan\n")
        elif protocol == "UDP":
            logging.info("Starting - UDP Port Scan\n")
        else:
            pass

        if end:
            for port in range(start,end):
                scan = self.port_scan(stealth,port=port)

                if scan:
                    ports_saved = {
                        "open": open_ports,
                        "filtered": filtered_ports,
                        "open/filtered": open_or_filtered
                    }

                    open_ports, filtered_ports, open_or_filtered = self.handle_port_response(ports_saved=ports_saved,response=scan,port=port)

            if open_ports or filtered_ports or open_or_filtered:
                total = len(open_ports) + len(filtered_ports) + len(open_or_filtered)

                # print_figlet()
                logging.info(f"Founded {total} ports!")

                for port in open_ports:
                    logging.info(f"Port: {port} - Open")
                for port in filtered_ports:
                    logging.warning(f"Port: {port} - Filtered")
                for port in open_or_filtered:
                    logging.info(f"Port: {port} - Open/Filtered")
        else:
            scan = self.port_scan(stealth)

            if scan:
                    ports_saved = {
                        "open": open_ports,
                        "filtered": filtered_ports,
                        "open/filtered": open_or_filtered
                    }

                    open_ports, filtered_ports, open_or_filtered = self.handle_port_response(ports_saved=ports_saved,response=scan,port=start)

            if open_ports or filtered_ports or open_or_filtered:
                total = len(open_ports) + len(filtered_ports) + len(open_or_filtered)

                # print_figlet()
                logging.info(f"Founded {total} ports!")

                for port in open_ports:
                    logging.info(f"Port: {port} - Open")
                for port in filtered_ports:
                    logging.debug(f"Port: {port} - Filtered")
                for port in open_or_filtered:
                    logging.info(f"Port: {port} - Open/Filtered")

    def os_scan(self):
        target_os = os_detection.scan(self.target)
        
        if target_os:
            print("")
            logging.info(f"Target OS: {target_os}")
        else:
            logging.warning("[[red]-[/red]]Error when scanning OS")

    def send_icmp(self,target, result, index):
        # print(f"[+]Sending ICMP request to {target}")
        target = str(target)
        host_found = []
        pkg = IP(dst=target)/ICMP()
        answers, unanswered = sr(pkg,timeout=3, retry=2,verbose=0,iface=self.interface if self.interface else None)
        answers.summary(lambda r : host_found.append(target))

        if host_found: result[index] = host_found[0]

    def discover_net(self,ip_range=24):
        protocol = self.protocol
        base_ip = self.my_ip

        # print_figlet()

        if not protocol:
            protocol = "ICMP"
        else:
            if protocol != "ICMP":
                logging.warning(f"Warning: {protocol} is not supported by discover_net function! Changed to ICMP")

        if protocol == "ICMP":
            logging.info("Starting - Discover Hosts Scan")

            base_ip = base_ip.split('.')
            base_ip = f"{str(base_ip[0])}.{str(base_ip[1])}.{str(base_ip[2])}.0/{str(ip_range)}"

            hosts = list(ipaddress.ip_network(base_ip))
            bar = ChargingBar("Scanning...", max=len(hosts))

            sys.stdout = None
            bar.start()

            threads = [None] * len(hosts)
            results = [None] * len(hosts)

            for i in range(len(threads)):
                threads[i] = Thread(target=self.send_icmp,args=(hosts[i], results, i))
                threads[i].start()

            for i in range(len(threads)):
                threads[i].join()
                bar.next()

            bar.finish()
            sys.stdout = sys.__stdout__

            hosts_found = [i for i in results if i is not None]

            if not hosts_found:
                logging.warn('[[red]-[/red]]Not found any host')
            else:
                print("")
                logging.info(f'{len(hosts_found)} hosts founded')
                for host in hosts_found:
                    logging.info(f'Host found: {host}')
            
            return True
        else:
            logging.critical("[[red]-[/red]]Invalid protocol for this scan")

            return False

def arguments():
    parser = argparse.ArgumentParser(description="ASTSU - Network Tool",usage="\n\tastsu.py -sC 192.168.0.106\n\tastsu.py -sA 192.168.0.106")
    
    parser.add_argument('-sC',"--scan-common",help="Scan common ports",action="count")
    parser.add_argument('-sA',"--scan-all",help="Scan all ports",action="count")
    parser.add_argument('-sO',"--scan-os",help="Scan OS",action="count")
    parser.add_argument('-sP',"--scan-port",help="Scan defined port")
    parser.add_argument('-sV',"--scan-service",help="Try to detect service running")
    parser.add_argument('-d',"--discover",help="Discover hosts in the network",action="count")
    parser.add_argument('-p',"--protocol",help="Protocol to use in the scans. ICMP,UDP,TCP.",type=str,choices=['ICMP','UDP','TCP'],default=None)
    parser.add_argument('-i',"--interface",help="Interface to use",default=None)
    parser.add_argument('-t',"--timeout",help="Timeout to each request",default=5,type=int)
    parser.add_argument('-st',"--stealth",help="Use Stealth scan method (TCP)",action="count")
    parser.add_argument('-v',"--verbose",action="count")
    parser.add_argument('Target',nargs='?',default=None)

    args = parser.parse_args()

    if not args.discover and not args.Target:
        sys.exit(parser.print_help())

    if not args.scan_common and not args.scan_all and not args.scan_os and not args.scan_port and not args.discover:
        sys.exit(parser.print_help())

    return (args, parser)

if __name__ == '__main__':
    args, parser = arguments() 

    del logging.root.handlers[:]
  
    logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
    logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
    logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
    logging.addLevelName(logging.DEBUG, f"[{cyan}**{reset}]")
    logging.basicConfig(format="%(levelname)s%(message)s", level=logging.DEBUG if args.verbose else logging.INFO)

    print_figlet()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8",80))
    ip = s.getsockname()[0]
    s.close()

    scanner = Scanner(target=args.Target,my_ip=ip,protocol=args.protocol,timeout=args.timeout,interface=args.interface)

    if args.scan_common:
        scanner.common_scan(stealth=args.stealth,sv=args.scan_service)

    elif args.scan_all:
        scanner.range_scan(start=0,end=65535,stealth=args.stealth,sv=args.scan_service)

    elif args.scan_port:
        try:
            scanner.range_scan(start=int(args.scan_port.split(',')[0]),end=int(args.scan_port.split(',')[1]),stealth=args.stealth,sv=args.scan_service)
        except:
            scanner.range_scan(start=args.scan_port,stealth=args.stealth,sv=args.scan_service)

    elif args.discover:
        scanner.discover_net() 

    else:
        parser.print_help()

    if args.scan_os:
        scanner.os_scan()