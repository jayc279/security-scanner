# FastMCP Security Scanner Server

An enterprise-ready Model Context Protocol (MCP) server built with Python FastMCP. This server exposes secure wrappers for nmap directly to Claude Code and Cursor, allowing automated workflows to query network architectures, discover open ports, fingerprint operating systems, and check for software vulnerabilities.

## Architecture and Directory Layout

This project uses a modular, decoupled layout that automatically registers new tools found inside the hidden local configuration path:

```text
├── .claude/
│   └── skills/
│       └── port-scan/
│           ├── SKILL.md                 # Systemic discovery definitions for Claude Code
│           └── scripts/
│               ├── __init__.py
│               ├── perform_scan.py      # Boundary Map Tool (@mcp.tool)
│               ├── detect_os.py         # OS Signature Tool (@mcp.tool)
│               └── detect_vulns.py      # Threat Listing Tool (@mcp.tool)
├── pyproject.toml                       # Build manifests and dependencies (uv/hatchling)
├── local_scanner.py                     # Main FastMCP Server Hub and Dynamic Coordinator
└── test_scanner.py                      # Complete mock-isolated unit test suite
```

## Security and Defensive Guardrails

- Pre-Flight Binary Verification: The server will gracefully fail-closed on startup if the underlying system-level nmap binary is missing, preventing raw unhandled tracebacks.
- Input Sanitization: Host parameters are stripped and validated to protect the server from shell injection or malicious target arguments.
- Mock-Isolated Testing: The unit test suite completely isolates the network layer, ensuring zero traffic escapes to the host interface during test routines.

## Getting Started

### 1. Prerequisites
Ensure you have the Python uv package manager and the host-level nmap binary installed:

```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt-get install nmap

# Windows
# Download and install the binaries from https://nmap.org
```

### 2. Development Setup and Testing
Install project dependencies and verify the architecture using the pre-configured test suite:

```bash
# Clone and enter the repository directory
cd security-scanner

# Execute the test suite to verify module registration and mocking
uv run pytest test_scanner.py -v
```

### 3. Registering the Server with Claude Code
To link this server locally to your workspace environment for immediate development profiling, execute the standard discovery command:
```bash
claude mcp add security-scanner --scope project -- uv run local_scanner.py
```

## Adding New Scanning Capabilities

The architecture uses a zero-maintenance dynamic registration model. To create a new network capability:

1. Drop a new script into `.claude/skills/port-scan/scripts/` (e.g., `dns_lookup.py`).
2. Import the shared mcp server context at the top of your file.
3. Apply the `@mcp.tool()` decorator to your primary function.

```python
from local_scanner import mcp

@mcp.tool()
def identify_dns_records(target: str) -> dict:
    """Analyze target network zones to resolve active records."""
    # Your network parsing logic here
    return {"status": "complete"}
```

The `local_scanner.py` engine will automatically discover, ingest, and present the new tool to Claude Code on the next launch.
