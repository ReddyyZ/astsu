from nmap_vscan import vscan
import sys,platform,os,logging

def scan_service(target,port):
    # Get the path to service_probes relative to this module
    module_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    service_probes_path = os.path.join(module_dir, 'service_probes')
    
    # Fall back to system paths if local file doesn't exist
    if not os.path.exists(service_probes_path):
        if platform.system() == 'Linux':
            service_probes_path = '/usr/share/astsu/service_probes'
        elif platform.system() == 'Windows':
            service_probes_path = 'C:\\astsu\\service_probes'
    
    try:
        nmap = vscan.ServiceScan(service_probes_path)
        result = nmap.scan(str(target), int(port), 'tcp')
    except Exception as e:
        logging.error(f"Service scan failed for {target}:{port} - {e}")
        return None
    service_name = str(result['match']['versioninfo']['cpename'])
    
    service_name = service_name.replace('[','')
    service_name = service_name.replace(']','')
    service_name = service_name.replace("'","",2)

    if not service_name:
        service_name = 'Not found any service'
    return service_name