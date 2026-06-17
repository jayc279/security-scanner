import sys
import os
import pytest
from unittest.mock import MagicMock, patch

# Ensure the scripts directory is in the path so pytest can find the modules
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_PATH = os.path.join(BASE_DIR, ".claude", "skills", "port-scan", "scripts")
if SCRIPTS_PATH not in sys.path:
    sys.path.insert(0, SCRIPTS_PATH)

# Import the main scanner module
import local_scanner

# -----------------------------------------------------------------------------
# 1. FIXTURES & DYNAMIC SETUP
# -----------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def setup_and_register_tools():
    """Automatically registers tools before each test runs."""
    # Ensure system binary check doesn't crash the test runner
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        local_scanner.register_dynamic_tools()

# -----------------------------------------------------------------------------
# 2. DYNAMIC TOOL FUNCTIONALITY TESTS
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dynamic_scan_infrastructure_ports():
    """Verifies that the dynamically loaded port scan tool works correctly."""
    # Import the script directly to mock its internal scanning function
    import perform_scan
    
    expected_output = {"target": "127.0.0.1", "status": "success", "results": {}}
    
    # We patch the underlying logic inside the file, leaving the tool wrapper intact
    with patch.object(perform_scan, "scan_infrastructure_ports", return_value=expected_output):
        # Invoke the tool via local_scanner's registered tool list
        result = await local_scanner.scan_infrastructure_ports("127.0.0.1", "80")
        assert result == expected_output


@pytest.mark.asyncio
async def test_dynamic_detect_host_operating_system():
    """Verifies that the dynamically loaded OS discovery tool works correctly."""
    import detect_os
    
    expected_output = {"target": "192.168.1.1", "os": "Linux"}
    
    with patch.object(detect_os, "detect_host_operating_system", return_value=expected_output):
        result = await local_scanner.detect_host_operating_system("192.168.1.1")
        assert result == expected_output


@pytest.mark.asyncio
async def test_dynamic_audit_port_vulnerabilities():
    """Verifies that the dynamically loaded vulnerability audit tool works correctly."""
    import detect_vulns
    
    expected_output = {"target": "localhost", "port": 22, "vulns": []}
    
    with patch.object(detect_vulns, "audit_port_vulnerabilities", return_value=expected_output):
        result = await local_scanner.audit_port_vulnerabilities("localhost", 22)
        assert result == expected_output

# -----------------------------------------------------------------------------
# 3. SYSTEM GATING TESTS
# -----------------------------------------------------------------------------

def test_verify_system_binary_failure():
    """Ensures server halts startup gracefully if the host is missing nmap."""
    with patch("shutil.which", return_value=None), \
         patch("sys.stderr"):
        
        with pytest.raises(SystemExit) as exit_info:
            local_scanner.verify_system_binary()
            
        assert exit_info.value.code == 1
