import argparse
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
import nmap

def run_scan(target):
    nm = nmap.PortScanner()
    print(f"[*] Starting scan on target: {target}")
    # Running a standard SYN scan with service detection
    nm.scan(hosts=target, arguments='-sV -T4')
    return nm.get_nmap_last_output()

def parse_and_generate_report(xml_data, target):
    root = ET.fromstring(xml_data)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"report_{target.replace('/', '_')}_{timestamp}.md"
    
    with open(report_filename, "w") as f:
        f.write(f"# Network Reconnaissance Report\n\n")
        f.write(f"**Target:** {target}  \n")
        f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n\n")
        f.write("## Open Ports & Services\n\n")
        f.write("| Port | Protocol | State | Service | Version |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        
        for host in root.findall('host'):
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    portid = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state').get('state')
                    
                    service_elem = port.find('service')
                    service = service_elem.get('name') if service_elem is not None else "unknown"
                    product = service_elem.get('product', '') if service_elem is not None else ""
                    version = service_elem.get('version', '') if service_elem is not None else ""
                    ext_version = f"{product} {version}".strip() or "N/A"
                    
                    if state == 'open':
                        f.write(f"| {portid} | {protocol} | {state} | {service} | {ext_version} |\n")
                        
    print(f"[+] Report successfully generated: {report_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Nmap Recon Reporter")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR range")
    args = parser.parse_args()
    
    try:
        xml_output = run_scan(args.target)
        parse_and_generate_report(xml_output, args.target)
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        sys.exit(1)
