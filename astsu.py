#!/usr/bin/env python

# -*- coding:utf-8 -*-
import os,sys,socket,ipaddress,argparse
from scapy.all import *  
from ctypes import *
from time import sleep
from modules import service_detection,os_detection

if os.name == 'nt':
    clear = lambda:os.system('cls')
else:
    clear = lambda:os.system('clear')
    

def print_figlet():
    clear()
    print(
    '''
    .d8b.  .d8888. d888888b .d8888. db    db 
    d8' `8b 88'  YP `~~88~~' 88'  YP 88    88 
    88ooo88 `8bo.      88    `8bo.   88    88 
    88~~~88   `Y8b.    88      `Y8b. 88    88 
    88   88 db   8D    88    db   8D 88b  d88 
    YP   YP `8888Y'    YP    `8888Y' ~Y8888P' 
    '''
    )

def common_scan(target):
    print_figlet()
    
    ports = [21,22,80,443,3306,14147,2121,8080,8000]
    open_ports = {}
    print('[+] Starting..')
    
    for port in ports:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        if sock.connect_ex((target,port)) == 0:
            open_ports['{}'.format(port)] = '{}'.format(service_detection.scan_service(target,port))

    if open_ports:
        print('[+] {} ports founded'.format(len(open_ports)))
    else:
        print('[-] Not found any open ports.')
    
    for port in open_ports:
        print('[+] Port {} is open - Service Running: {}'.format(port,open_ports[port]))

def discover_net(base_ip,ip_range=24,protocol="ICMP",interface=None):
    print_figlet()

    if protocol == "ICMP":
        base_ip = base_ip.split('.')
        base_ip = f"{str(base_ip[0])}.{str(base_ip[1])}.0.0/{str(ip_range)}"
        hosts_found = []

        hosts = list(ipaddress.ip_network(base_ip))

        for i in hosts:
            try:
                target = str(i)

                pkg = IP(dst=target)/ICMP()
                # answers, unanswered = sr(pkg,retry=0,timeout=1.1,inter=0.2,verbose=0)
                if interface:
                    answers, unanswered = sr(pkg,timeout=1,verbose=0,iface=interface)
                else:
                    answers, unanswered = sr(pkg,timeout=1,verbose=0)
                print(f"[+]Sending ICMP request to {target}")
                answers.summary(lambda r : hosts_found.append(target))
            except:
                pass
        
        if not hosts_found:
            print('[-] Not found any host')
        else:
            print(f'\n[+] {len(hosts_found)} hosts founded')
            for host in hosts_found:
                print(f'[+] Host found: {host}')
    else:
        print("[-]Invalid protocol for this scan")
        
    return True

def os_scan(target,interface=None):
    print_figlet()

    target_os = os_detection.scan(target)
    
    if target_os:
        print('[+] Target OS: {}'.format(target_os))
    else:
        print('[-] Error when scanning OS')

def scan_this_port(target,_from,to=None):
    print_figlet()

    if to:

        ports = {}

        for port in range(_from,to):
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        
            if sock.connect_ex((target,port)) == 0:
                service = service_detection.scan_service(target,port)
                print('[+] Port: {} is open - Service Running: {}'.format(port,service))
                ports[port] = service
            else:
                print('[-] Port: {} is closed'.format(port))
        
        print_figlet()
        
        if ports:
            print(f"[+] {len(ports)} open ports")
            for port in ports:
                print(f"[+] Port: {port} is open - Service Running: {ports[port]}")
        else:
            print("[-] Not found any port")
    else:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        
        if sock.connect_ex((target,_from)) == 0:
            service = service_detection.scan_service(target,_from)
            print('[+] Port: {} is open - Service Running: {}'.format(_from,service))
        else:
            print('[-] Port: {} is closed'.format(_from))        

def scan_all(target):
    print_figlet()

    ports = []

    for i in range(0,65535):
        ports.append(i)

    open_ports = {}
    print('[+] Starting..')

    for port in ports:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(0.3)
        if sock.connect_ex((target,port)) == 0:
            open_ports['{}'.format(port)] = '{}'.format(service_detection.scan_service(target,port))

    if open_ports:
        print('[+] {} ports founded'.format(len(open_ports)))
    else:
        print('[-] Not found any open ports.')
    for port in open_ports:
        print('[+] Port {} is open - Service Running: {}'.format(port,open_ports[port]))

def arguments():
    parser = argparse.ArgumentParser(description="ASTSU - Network Tool",usage="\n\tastsu.py -sC 192.168.0.106\n\tastsu.py -sA 192.168.0.106")
    
    parser.add_argument('-sC',"--scan-common",help="Scan common ports",action="count")
    parser.add_argument('-sA',"--scan-all",help="Scan all ports",action="count")
    parser.add_argument('-sO',"--scan-os",help="Scan OS",action="count")
    parser.add_argument('-sP',"--scan-port",help="Scan defined port",nargs='+',type=int)
    parser.add_argument('-d',"--discover",help="Discover hosts in the network",action="count")
    parser.add_argument('-p',"--protocol",help="Protocol to use in the scans. ICMP,UDP,TCP.",type=str,choices=['ICMP','UDP','TCP'])
    parser.add_argument('-i',"--interface",help="Interface to use")
    parser.add_argument('Target',nargs='?')

    args = parser.parse_args()

    return (args, parser)

if __name__ == '__main__':
    args, parser = arguments() 
    
    if args.scan_common:
        if not args.Target:
            sys.exit(parser.print_help())
        
        common_scan(args.Target)

    elif args.scan_all:
        if not args.Target:
            sys.exit(parser.print_help())
        
        scan_all(args.Target)

    elif args.scan_os:
        if not args.Target:
            sys.exit(parser.print_help())

        if args.interface:        
            os_scan(args.Target,args.interface)
        else:
            os_scan(args.Target)

    elif args.scan_port:
        if not args.Target:
            sys.exit(parser.print_help())
        
        try:
            scan_this_port(target=args.Target,_from=args.scan_port[0],to=args.scan_port[1])
        except:
            scan_this_port(target=args.Target,_from=args.scan_port[0])

    elif args.discover:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80))
        ip = s.getsockname()[0]
        s.close()

        if args.protocol:
            if args.interface:
                discover_net(base_ip=ip,protocol=args.protocol,interface=args.interface)
            else:
                discover_net(base_ip=ip,protocol=args.protocol)   
        else:
            if args.interface:
                discover_net(base_ip=ip,interface=args.interface)
            else:
                discover_net(base_ip=ip)

    else:
        parser.print_help()

# teste
