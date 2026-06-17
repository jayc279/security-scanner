import re
from local_scanner import mcp

# Strict IPv4 and Domain Name Validation Patterns
IP_REGEX = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
DOMAIN_REGEX = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"

@mcp.tool()
def audit_port_vulnerabilities(target: str, port: int) -> dict:
    """Inspect application layers to identify known vulnerabilities.
    
    Args:
        target: The target IP address or domain name to audit.
        port: The specific target port integer to assess (1-65535).
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
        
    try:
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            raise ValueError()
    except (ValueError, TypeError):
        return {
            "status": "error",
            "error_type": "ValidationError",
            "message": f"Invalid port entry: '{port}'. Port must be an integer between 1 and 65535."
        }

    # 2. Execution and Error Handling Phase
    try:
        import nmap
        
        nm = nmap.PortScanner()
        # Uses Nmap Scripting Engine (NSE) vulnerability script against the specific target port
        scan_args = f"-p {port_int} -sV --script=vuln"
        nm.scan(hosts=clean_target, arguments=scan_args)
        
        vuln_data = {}
        if clean_target in nm.all_hosts():
            vuln_data = nm[clean_target]

        return {
            "target": clean_target,
            "port_audited": port_int,
            "status": "success",
            "vulnerability_report": vuln_data
        }

    except nmap.PortScannerError as e:
        return {
            "status": "error",
            "error_type": "NmapExecutionError",
            "message": f"Underlying network utility failure during vulnerability audit: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "error_type": "SystemError",
            "message": f"An unexpected runtime exception occurred: {str(e)}"
        }
