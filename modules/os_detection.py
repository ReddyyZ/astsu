from scapy.all import *

def scan(target,interface=None):
    """
    Detect OS based on TTL value from ICMP response.
    Common default TTL values:
    - Linux/Unix: 64
    - Windows: 128  
    - Cisco/Network Equipment: 255
    - Windows 95/98: 32
    """
    try:
        # TTL value -> OS mapping (more efficient lookup)
        ttl_to_os = {
            32: 'Windows 95/98',
            64: 'Linux/Unix',
            128: 'Windows',
            255: 'Unix/BSD/Network Equipment'
        }
        pkg = IP(dst=target,ttl=128)/ICMP()

        if interface:
            ans, uns = sr(pkg,retry=5,timeout=3,inter=1,verbose=0,iface=interface)
        else:
            ans, uns = sr(pkg,retry=5,timeout=3,inter=1,verbose=0)

        try:
            target_ttl = ans[0][1].ttl
        except (IndexError, AttributeError):
            print("[-] Host did not respond")
            return False

        # Direct match
        if target_ttl in ttl_to_os:
            return ttl_to_os[target_ttl]
        
        # TTL decreases with each hop, so check ranges
        if target_ttl <= 64:
            return f'Linux/Unix (TTL: {target_ttl})'
        elif target_ttl <= 128:
            return f'Windows (TTL: {target_ttl})'
        else:
            return f'Unix/BSD/Network Equipment (TTL: {target_ttl})'
            
    except Exception:
        return False
