# ContrastScan MCP Server

MCP server that lets AI agents scan domains for security issues via [ContrastScan](https://contrastcyber.com).

## Tools

| Tool | Description |
|------|-------------|
| `scan_domain` | Full security scan — 11 modules, A-F grade, findings with remediation |
| `get_report` | Plain-text security report with passive recon (WHOIS, tech stack, subdomains) |
| `check_grade` | Quick grade check — just the letter grade and score |

## Setup

### Claude Code

```bash
claude mcp add contrastcyber -- python /path/to/mcp/server.py
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "contrastcyber": {
      "command": "python",
      "args": ["/path/to/mcp/server.py"]
    }
  }
}
```

### Install from source

```bash
cd mcp/
pip install -e .
mcp-contrastcyber
```

## Example

Ask Claude: *"Scan example.com for security issues"* — it will call `scan_domain` and return the grade, module scores, and findings.
