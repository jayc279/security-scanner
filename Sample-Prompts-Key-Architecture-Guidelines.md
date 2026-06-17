# Sample Prompts &  Key Architectural Guidelines for Client Interaction

## Key Architectural Guidelines for Client Interaction
## Explicit Naming Constraints
Use the exact Python function name in your text prompt. Claude Code maps your intent string directly to the registered tools

### Deterministic Restrictions
Always include a strict boundary instruction like "Do not execute any secondary scans" or "Run only this tool". This overrides the AI's agentic behavior and stops it from automatically chaining tools together (such as checking vulnerabilities right after a scan finishes).

### Parameter Clarity
Provide all required variables directly inside your phrase so the client does not pause to ask you follow-up clarification questions.

## Sample Prompts
Using explicit keyword commands in your prompts tells Cursor or Claude Code exactly which capability to trigger. Because you built this server using Python's FastMCP framework, the functions you decorated with @mcp.tool() are translated into discrete tool tools exposed to the AI client.

To invoke a specific tool, use the corresponding prompt structure below.

## Standard Prompt Templates

### Only Port Scanner
- Run scan_infrastructure_ports on target 127.0.0.1 scanning ports 80,443. Do not run any other tools.

### Only O.S. Detection
- Invoke the detect_host_operating_system tool for target 192.168.1.1.

### Only Vulnerability Audit
- Execute the audit_port_vulnerabilities tool against target localhost on port 22


