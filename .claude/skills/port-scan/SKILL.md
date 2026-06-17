---
name: security-scanner
description: Automates low-level network footprinting, vulnerability lookup workflows, and target OS identification.
---

# Skill: FastMCP Infrastructure Security Scanner

## Purpose
Enables programmatic local footprint analysis, OS determination, and package vulnerability discovery by abstracting Nmap bindings into structured Model Context Protocol endpoints.

## Directory Layout Hierarchy
- **Configuration Master**: `./claude/skills/port-scan/SKILL.md`
- **MCP Server Engine**: `./local_scanner.py`
- **Execution Script Hub**:
 - Boundary Map: `./claude/skills/port-scan/scripts/perform_scan.py`
 - Platform Signature: `./claude/skills/port-scan/scripts/detect_os.py`
 - Threat Listing: `./claude/skills/port-scan/scripts/detect_vulns.py`

## Activation Prompts & Hooks
- Trigger when analyzing server configuration blueprints or open network channels.
- Trigger when determining software patch versions or looking up systemic security exposures (CVEs).

## Orchestration Details
1. Claude matches runtime demands to this specific documentation blueprint.
2. Dependencies are parsed natively through standard system channels via the `uv` tool belt.
3. The platform invokes the targeted script capability handled by the underlying execution script bundle.
