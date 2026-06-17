# Import the shared mcp instance from your main file
from local_scanner import mcp

import re

# Strict IPv4 and Domain Name Validation Patterns
IP_REGEX = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
DOMAIN_REGEX = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"

@mcp.tool()
def scan_infrastructure_ports(target: str, ports: str = "1-100") -> dict:
    """Run a safe network boundary port scan against a designated host.
    
    Args:
        target: The target IP address or domain name.
        ports: A comma-separated list or range of ports (e.g., '80,443' or '1-1024').
    """
    clean_target = target.strip()
    
    # 1. Input Validation Phase
    is_ip = re.match(IP_REGEX, clean_target)
    is_domain = re.match(DOMAIN_REGEX, clean_target)
    
    if not (is_ip or is_domain) or clean_target == "0.0.0.0":
        return {
            "status": "error",
            "error_type": "ValidationError",
            "message": f"Rejected target format: '{clean_target}'. Input must be a valid IPv4 address or standard domain name."
        }

    # 2. Execution and Error Handling Phase
    try:
        # Import inside the function to keep tool loading fast
        import nmap
        
        nm = nmap.PortScanner()
        # Execute nmap with arguments that prevent dns resolution loops (-n)
        nm.scan(hosts=clean_target, ports=ports, arguments="-n -sT")
        
        # Structure the scan results safely
        scan_data = {}
        if clean_target in nm.all_hosts():
            scan_data = nm[clean_target]

        return {
            "target": clean_target,
            "ports_scanned": ports,
            "status": "success",
            "results": scan_data
        }

    except nmap.PortScannerError as e:
        return {
            "status": "error",
            "error_type": "NmapExecutionError",
            "message": f"Underlying network utility failure: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "error_type": "SystemError",
            "message": f"An unexpected runtime exception occurred: {str(e)}"
        }


