from scapy.all import *

def scan(target,interface=None):
    try:
        os_ttl = {'Linux/Unix 2.2-2.4 >':255,'Linux/Unix 2.0.x kernel':64,'Windows 98':32,'Windows':128}
        pkg = IP(dst=target,ttl=128)/ICMP()

        if interface:
            ans, uns = sr(pkg,retry=5,timeout=3,inter=1,verbose=0,iface=interface)
        else:
            ans, uns = sr(pkg,retry=5,timeout=3,inter=1,verbose=0)

        try:
            target_ttl = ans[0][1].ttl
        except:
            print("[-] Host did not respond")
            return False

        for ttl in os_ttl:
            if target_ttl == os_ttl[ttl]:
                return ttl
    except:
        return False
