#!/usr/bin/env python
import os,sys,socket
from scapy.all import *  
from time import sleep
from modules import service_detection,os_detection

if os.name == 'nt':
    clear = lambda:os.system('cls')
else:
    clear = lambda:os.system('clear')

def common_scan():
    print_figlet()
    print('[+] Target:')
    target = raw_input('root@kali~# ')
    
    ports = [21,22,80,443,2121,8080,8000]
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
    raw_input('\nPress enter...')

def discover_net():
    print_figlet()
    print('[+] Router IP(It will serve as a basis for mapping the network):')
    router_ip = raw_input('root@kali~# ')

    base_ip = router_ip.split('.')
    # base_ip = base_ip[0] + '.' + base_ip[1] + '.' + base_ip[2] + '.' + base_ip[3]
    hosts_found = []
    for i in range(0,255):
        target = base_ip
        target[3] = i
        target = str(target[0]) + '.' + str(target[1]) + '.' + str(target[2]) + '.' + str(target[3])
        try:
            pkg = IP(dst=target,ttl=1)/ICMP()
            answers, unanswered = sr(pkg,retry=0,timeout=0.2,inter=0.2,verbose=0)
            print('[+] Sending ICMP request to {}'.format(target))
            answers.summary(lambda r : hosts_found.append(target))
        except Exception as e:
            print(e)
            pass
    if not hosts_found:
        print('[-] Not found any host')
    else:
        print('\n[+] {} hosts founded'.format(len(hosts_found)))
        for host in hosts_found:
            print('[+] Host found: {}'.format(host))
        raw_input('\nPress enter...')

def os_scan():
    print_figlet()
    print('[+] Target:')
    target = raw_input('root@kali~# ')
    target_os = os_detection.scan(target)
    if target_os:
        print('[+] Target os: {}'.format(target_os))
    else:
        print('[-] Error when scanning os')
    raw_input('\nPress enter...')

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

def main():
    while True:
        print_figlet()

        print(
            '[1] Scan common ports\n'
            '[2] Discover hosts in network\n'
            '[3] Scan OS\n'
            '[4] Exit\n'
        )

        try:
            option = int(raw_input('root@kali~# '))
        except:
            print('[-] Invalid option')
            sleep(1)
            continue

        if option == 1:
            common_scan()
        elif option == 2:
            discover_net()
        elif option == 3:
            os_scan()
        elif option == 4:
            sys.exit(0)
        else:
            print('[-] Invalid option')
            sleep(1)

main()