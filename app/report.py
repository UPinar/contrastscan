"""Plain-text report generation for ContrastScan"""

import re

from config import REPORT_LINE_WIDTH
from fastapi.responses import Response

# Pre-compute reused separator strings (avoid repeated multiplication)
_SEP_EQUALS = "=" * REPORT_LINE_WIDTH
_SEP_DASH = "-" * REPORT_LINE_WIDTH

# Module display order: (label, result key)
_MODULES = [
    ("Security Headers", "headers"),
    ("SSL / TLS", "ssl"),
    ("DNS Security", "dns"),
    ("HTTP Redirect", "redirect"),
    ("Info Disclosure", "disclosure"),
    ("Cookie Security", "cookies"),
    ("DNSSEC", "dnssec"),
    ("HTTP Methods", "methods"),
    ("CORS", "cors"),
    ("HTML Analysis", "html"),
    ("CSP Analysis", "csp_analysis"),
]


def _module_detail_lines(key: str, mod: dict, details: dict) -> list[str]:
    """Return detail lines for a single module section."""
    lines: list[str] = []

    if key == "headers":
        for h in details if isinstance(details, list) else []:
            mark = "+" if h.get("present") else "-"
            lines.append(f"    {mark} {h.get('header', '')}")

    elif key == "ssl":
        if mod.get("error"):
            lines.append(f"    ! Error: {mod['error']}")
        else:
            lines.append(f"    TLS Version:    {details.get('tls_version', 'N/A')}")
            lines.append(f"    Cipher:         {details.get('cipher', 'N/A')}")
            cv = "Valid" if details.get("cert_valid") else "Invalid"
            lines.append(f"    Certificate:    {cv} ({details.get('days_remaining', 0)}d remaining)")
            ch = "Trusted" if details.get("chain_valid") else "Untrusted"
            lines.append(f"    Chain:          {ch}")

    elif key == "dns":
        for rec in ("spf", "dmarc", "dkim"):
            mark = "+" if details.get(rec) else "-"
            lines.append(f"    {mark} {rec.upper()}")

    elif key == "redirect":
        mark = "+" if details.get("redirects_to_https") else "-"
        lines.append(f"    {mark} HTTP -> HTTPS redirect")

    elif key == "disclosure":
        if details.get("server_exposed"):
            lines.append(f"    - Server header exposed: {details.get('server_value', '')}")
        else:
            lines.append("    + Server header hidden")
        if details.get("powered_by_exposed"):
            lines.append(f"    - X-Powered-By exposed: {details.get('powered_by_value', '')}")
        else:
            lines.append("    + X-Powered-By hidden")

    elif key == "cookies":
        cnt = details.get("cookies_found", 0)
        lines.append(f"    Cookies found: {cnt}")
        if cnt > 0:
            for flag in ("all_secure", "all_httponly", "all_samesite"):
                mark = "+" if details.get(flag) else "-"
                lines.append(f"    {mark} {flag.replace('all_', '').capitalize()}")

    elif key == "dnssec":
        mark = "+" if details.get("dnssec_enabled") else "-"
        lines.append(f"    {mark} DNSSEC enabled")

    elif key == "methods":
        for method in ("trace_enabled", "delete_enabled", "put_enabled"):
            name = method.replace("_enabled", "").upper()
            if details.get(method):
                lines.append(f"    - {name} enabled (dangerous)")
            else:
                lines.append(f"    + {name} disabled")

    elif key == "cors":
        if details.get("credentials_with_wildcard"):
            lines.append("    - Credentials with wildcard origin (critical)")
        if details.get("reflects_origin"):
            lines.append("    - Reflects arbitrary Origin header")
        elif details.get("wildcard_origin"):
            lines.append("    - Wildcard Access-Control-Allow-Origin")
        if (
            not details.get("wildcard_origin")
            and not details.get("reflects_origin")
            and not details.get("credentials_with_wildcard")
        ):
            lines.append("    + CORS properly restricted")

    elif key == "html":
        lines.append(f"    Mixed active:   {details.get('mixed_active', 0)}")
        lines.append(f"    Mixed passive:  {details.get('mixed_passive', 0)}")
        lines.append(f"    Inline scripts: {details.get('inline_scripts', 0)}")
        lines.append(f"    No SRI scripts: {details.get('external_scripts_no_sri', 0)}")
        lines.append(f"    HTTP forms:     {details.get('forms_http_action', 0)}")

    elif key == "csp_analysis":
        if not details.get("csp_present"):
            lines.append("    - CSP header not present")
        else:
            _csp_labels = {
                "unsafe_inline": ("unsafe-inline allowed", "No unsafe-inline"),
                "unsafe_eval": ("unsafe-eval allowed", "No unsafe-eval"),
                "wildcard_source": ("Wildcard source (*) allowed", "No wildcard sources"),
                "data_uri": ("data: URI allowed", "No data: URIs"),
            }
            for check, (bad_label, good_label) in _csp_labels.items():
                if details.get(check):
                    lines.append(f"    - {bad_label}")
                else:
                    lines.append(f"    + {good_label}")

    return lines


def _recon_section(recon: dict | None) -> list[str]:
    """Return the passive recon section lines."""
    if recon is None:
        return []
    lines: list[str] = []
    lines.append("")
    lines.append(_SEP_DASH)
    lines.append("  PASSIVE RECON")
    lines.append(_SEP_DASH)

    # 1. WHOIS — domain ownership
    whois = recon.get("whois", {})
    if whois and not whois.get("error"):
        lines.append("  WHOIS")
        if whois.get("registrar"):
            lines.append(f"    Registrar:  {whois['registrar']}")
        if whois.get("creation_date"):
            lines.append(f"    Created:    {whois['creation_date']}")
        if whois.get("expiry_date"):
            lines.append(f"    Expires:    {whois['expiry_date']}")
        ns = whois.get("name_servers", [])
        if ns:
            for n in ns:
                lines.append(f"    NS:         {n}")

    # 2. Infrastructure — IP, hosting
    rdns = recon.get("reverse_dns", {})
    if rdns.get("ip"):
        ptr_part = f" -> {rdns['ptr']}" if rdns.get("ptr") else ""
        lines.append(f"  Infrastructure: {rdns['ip']}{ptr_part}")

    # 3. Fingerprint — tech stack, WAF, protocol
    tech = recon.get("tech_stack", {})
    techs = tech.get("technologies", [])
    waf = recon.get("waf", {})
    hv = recon.get("http_version", {})
    fp_lines = []
    for t in techs:
        fp_lines.append(f"    - {t.get('name', '')} ({t.get('source', '')})")
    if waf.get("waf_present"):
        fp_lines.append(f"    - WAF: {', '.join(waf.get('detected', []))}")
    if hv:
        fp_lines.append(f"    - Protocol: {(hv.get('negotiated') or 'unknown').upper()}")
    if fp_lines:
        lines.append("  Fingerprint")
        lines.extend(fp_lines)

    # 4. Subdomains — attack surface
    subs = recon.get("subdomains", {})
    sub_list = subs.get("subdomains", [])
    if sub_list:
        lines.append(f"  Subdomains ({len(sub_list)})")
        for s in sub_list[:15]:
            lines.append(f"    - {s}")
        if len(sub_list) > 15:
            lines.append(f"    ... and {len(sub_list) - 15} more")

    # 5. Zone Transfer — critical finding
    zt = recon.get("zone_transfer", {})
    if zt.get("vulnerable"):
        lines.append(f"  Zone Transfer: VULNERABLE ({zt.get('record_count', 0)} records)")

    # 6. robots.txt — hidden paths
    robots = recon.get("robots", {})
    if robots.get("exists"):
        paths = robots.get("disallowed_paths", [])
        if paths:
            lines.append(f"  robots.txt ({len(paths)} disallowed)")
            for p in paths[:10]:
                lines.append(f"    - {p}")
            if len(paths) > 10:
                lines.append(f"    ... and {len(paths) - 10} more")

    # 7. CT Logs — certificate history
    ct = recon.get("ct_logs", {})
    total = ct.get("total_certificates", 0)
    if total > 0:
        lines.append(f"  CT Logs: {total} certificates found")

    # 8. Email — MX infrastructure
    emails = recon.get("emails", {})
    found = emails.get("found", [])
    if found:
        lines.append("  Email (MX)")
        for e in found:
            lines.append(f"    - {e}")

    return lines


def _findings_section(findings: list[dict]) -> list[str]:
    """Return the findings section lines."""
    if not findings:
        return []
    lines: list[str] = []
    lines.append("")
    lines.append(_SEP_DASH)
    lines.append(f"  FINDINGS ({len(findings)})")
    lines.append(_SEP_DASH)
    for f in findings:
        sev = f.get("severity", "info").upper()
        lines.append(f"  [{sev}] {f.get('attack_vector', '')}")
        lines.append(f"    {f.get('description', '')}")
        lines.append(f"    Fix: {f.get('remediation', '')}")
        lines.append("")
    return lines


def generate_report(r: dict, scan_id: str, created_at: str, recon: dict | None = None) -> str:
    """Generate plain-text security report from scan result"""
    domain = r.get("domain", "unknown")
    grade = r.get("grade", "?")
    total = r.get("total_score", 0)
    max_s = r.get("max_score", 100)

    lines: list[str] = []

    # Header
    lines.append(_SEP_EQUALS)
    lines.append("  ContrastScan Security Report")
    lines.append("  https://contrastcyber.com")
    lines.append(_SEP_EQUALS)
    lines.append("")
    lines.append(f"  Domain:  {domain}")
    lines.append(f"  Grade:   {grade}")
    lines.append(f"  Score:   {total}/{max_s}")
    lines.append(f"  Date:    {created_at}")
    lines.append("")
    lines.append(_SEP_DASH)
    lines.append("  MODULE BREAKDOWN")
    lines.append(_SEP_DASH)

    # Module sections
    for name, key in _MODULES:
        mod = r.get(key, {})
        s = mod.get("score", 0)
        m = mod.get("max", 0)
        status = "PASS" if s == m else ("PARTIAL" if s > 0 else "FAIL")
        lines.append(f"  {name:<22} {s:>3}/{m:<3}  [{status}]")
        lines.extend(_module_detail_lines(key, mod, mod.get("details", {})))

    # Findings
    lines.extend(_findings_section(r.get("findings", [])))

    # Passive recon
    lines.extend(_recon_section(recon))

    # Footer
    lines.append(_SEP_DASH)
    lines.append(f"  Full result: https://contrastcyber.com/result/{scan_id}")
    lines.append("  Powered by contrastscan (open source)")
    lines.append(_SEP_EQUALS)

    return "\n".join(lines) + "\n"


def report_response(text: str, domain: str) -> Response:
    safe_domain = re.sub(r"[^a-z0-9.-]", "", domain)
    return Response(
        content=text,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_domain}-security-report.txt"',
        },
    )
