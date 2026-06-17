import re
from local_scanner import mcp

# Strict IPv4 and Domain Name Validation Patterns
IP_REGEX = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
DOMAIN_REGEX = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"

@mcp.tool()
def detect_host_operating_system(target: str) -> dict:
    """Fingerprint target machines to safely deduce the host Operating System.
    
    Args:
        target: The target IP address or domain name to fingerprint.
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
        import nmap
        
        nm = nmap.PortScanner()
        # -O enables OS detection. This often requires sudo/root access.
        nm.scan(hosts=clean_target, arguments="-O --osscan-guess")
        
        os_matches = []
        if clean_target in nm.all_hosts() and "osmatch" in nm[clean_target]:
            os_matches = nm[clean_target]["osmatch"]

        return {
            "target": clean_target,
            "status": "success",
            "os_matches": os_matches
        }

    except nmap.PortScannerError as e:
        error_msg = str(e)
        # Check if the failure is due to missing root privileges for OS detection
        if "root" in error_msg.lower() or "privileges" in error_msg.lower():
            error_msg += " (OS detection '-O' typically requires root/administrator privileges)."
            
        return {
            "status": "error",
            "error_type": "NmapExecutionError",
            "message": f"Underlying network utility failure: {error_msg}"
        }
    except Exception as e:
        return {
            "status": "error",
            "error_type": "SystemError",
            "message": f"An unexpected runtime exception occurred: {str(e)}"
        }
