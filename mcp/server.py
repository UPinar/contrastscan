"""
ContrastScan MCP Server — security scanning tools for AI agents.

Usage:
  pip install mcp httpx
  python server.py

Or add to Claude Code / claude_desktop_config.json:
  {
    "mcpServers": {
      "contrastcyber": {
        "command": "python",
        "args": ["/path/to/server.py"]
      }
    }
  }
"""

import json
import httpx
from mcp.server.fastmcp import FastMCP

API_BASE = "https://contrastcyber.com"

mcp = FastMCP(
    "ContrastScan",
    description="Scan any domain for security misconfigurations — SSL/TLS, headers, DNS, CORS, cookies, and more.",
)


@mcp.tool()
def scan_domain(domain: str) -> str:
    """Scan a domain for security issues. Returns A-F grade, scores for 11 modules, and vulnerability findings with severity and remediation.

    Args:
        domain: The domain to scan (e.g. example.com)
    """
    resp = httpx.get(f"{API_BASE}/api/scan", params={"domain": domain}, timeout=30)
    if resp.status_code != 200:
        return f"Error {resp.status_code}: {resp.text}"

    data = resp.json()

    # Format a concise summary
    lines = [
        f"Domain: {data.get('domain', domain)}",
        f"Grade: {data.get('grade', '?')} ({data.get('total_score', 0)}/{data.get('max_score', 100)})",
        "",
        "Module Scores:",
    ]

    modules = [
        ("Security Headers", "headers"),
        ("SSL/TLS", "ssl"),
        ("DNS (SPF/DKIM/DMARC)", "dns"),
        ("HTTPS Redirect", "redirect"),
        ("Info Disclosure", "disclosure"),
        ("Cookie Security", "cookies"),
        ("DNSSEC", "dnssec"),
        ("HTTP Methods", "methods"),
        ("CORS", "cors"),
        ("HTML Analysis", "html"),
        ("CSP Analysis", "csp_analysis"),
    ]

    for label, key in modules:
        mod = data.get(key, {})
        score = mod.get("score", 0)
        max_s = mod.get("max", 0)
        status = "PASS" if score == max_s else "FAIL" if score == 0 else "WARN"
        lines.append(f"  {label}: {score}/{max_s} [{status}]")

    findings = data.get("findings", [])
    if findings:
        counts = data.get("findings_count", {})
        lines.append(f"\nFindings ({len(findings)}):")
        for sev in ("critical", "high", "medium", "low"):
            c = counts.get(sev, 0)
            if c > 0:
                lines.append(f"  {sev.upper()}: {c}")

        lines.append("")
        for f in findings[:10]:
            lines.append(f"  [{f.get('severity', '?').upper()}] {f.get('category', '')}: {f.get('description', '')}")
            if f.get("remediation"):
                lines.append(f"    Fix: {f['remediation']}")

        if len(findings) > 10:
            lines.append(f"  ... and {len(findings) - 10} more findings")

    return "\n".join(lines)


@mcp.tool()
def get_report(domain: str) -> str:
    """Get a full plain-text security report for a domain, including passive recon (WHOIS, tech stack, subdomains).

    Args:
        domain: The domain to scan (e.g. example.com)
    """
    resp = httpx.get(f"{API_BASE}/api/report", params={"domain": domain}, timeout=30)
    if resp.status_code != 200:
        return f"Error {resp.status_code}: {resp.text}"
    return resp.text


@mcp.tool()
def check_grade(domain: str) -> str:
    """Quick check — get just the security grade (A-F) and score for a domain.

    Args:
        domain: The domain to check (e.g. example.com)
    """
    resp = httpx.get(f"{API_BASE}/api/scan", params={"domain": domain}, timeout=30)
    if resp.status_code != 200:
        return f"Error {resp.status_code}: {resp.text}"

    data = resp.json()
    return f"{data.get('domain', domain)}: Grade {data.get('grade', '?')} ({data.get('total_score', 0)}/{data.get('max_score', 100)})"


if __name__ == "__main__":
    mcp.run()
