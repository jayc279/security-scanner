import sys
import os
import shutil
import glob
import importlib
from mcp.server.fastmcp import FastMCP

# 1. Initialize FastMCP Server first so scripts can import it
mcp = FastMCP("Web-Security-Scanner")

# 2. Resolve and expose the deep scripts directory to Python's search path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_PATH = os.path.join(BASE_DIR, ".claude", "skills", "port-scan", "scripts")
if SCRIPTS_PATH not in sys.path:
    sys.path.insert(0, SCRIPTS_PATH)

def verify_system_binary():
    """Verify system-level nmap binary is available before launch."""
    if not shutil.which("nmap"):
        print(
            "CRITICAL ERROR: The system 'nmap' binary was not found.\n"
            "Please install nmap on your host machine to run this toolkit.",
            file=sys.stderr
        )
        sys.exit(1)

def register_dynamic_tools():
    """Automatically imports all modules in the scripts folder to register tools."""
    # Find all Python files inside your scripts directory
    script_files = glob.glob(os.path.join(SCRIPTS_PATH, "*.py"))
    
    for file_path in script_files:
        module_name = os.path.basename(file_path)[:-3]  # Strip the '.py' extension
        if module_name != "__init__":
            try:
                # Importing the module triggers its internal @mcp.tool decorators
                importlib.import_module(module_name)
            except Exception as e:
                print(f"WARNING: Failed to dynamically load tool '{module_name}': {e}", file=sys.stderr)

def run_server():
    """Main entry point invoked by the Claude Code process runtime."""
    verify_system_binary()
    register_dynamic_tools()  # Automatically discovers and binds all tools
    mcp.run()

if __name__ == "__main__":
    run_server()
