from nmap_vscan import vscan
import sys,platform

def scan_service(target,port):
    return True

    if platform.system() == 'Linux':
        nmap = vscan.ServiceScan('/usr/share/astsu/service_probes')
    elif platform.system() == 'Windows':
        nmap = vscan.ServiceScan('C:\\Projetos\\Tools\\Network Tool\\service_probes')
    try:
        result = nmap.scan(str(target), int(port), 'tcp')
    except Exception as e:
        return e
    service_name = str(result['match']['versioninfo']['cpename'])
    
    service_name = service_name.replace('[','')
    service_name = service_name.replace(']','')
    service_name = service_name.replace("'","",2)

    if not service_name:
        service_name = 'Not found any service'
    return service_name