from scapy.all import *

def scan(target):
    try:
        os_ttl = {'Linux/Unix 2.2-2.4 >':255,'Linux/Unix 2.0.x kernel':64,'Windows 98':32,'Windows':128}
        pkg = IP(dst=target,ttl=128)/ICMP()
        ans, uns = sr(pkg,retry=2,timeout=10,inter=1,verbose=0)
        target_ttl = ans[0][1].ttl
        for ttl in os_ttl:
            if target_ttl == os_ttl[ttl]:
                return ttl
    except:
        return False
