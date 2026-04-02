"""Passive recon modules for ContrastScan — runs async after security scan"""

import json
import logging
import re
import socket
import ssl
import subprocess
import threading
from urllib.request import HTTPRedirectHandler, Request, build_opener

import dns.resolver
from config import CRTSH_TIMEOUT, RECON_TIMEOUT
from db import create_recon, save_recon, save_recon_error, save_recon_partial
from validation import is_private_ip

logger = logging.getLogger("contrastscan")


class _NoRedirectHandler(HTTPRedirectHandler):
    """Block HTTP redirects to prevent SSRF via redirect to internal IPs."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_no_redirect_opener = build_opener(_NoRedirectHandler)

CRTSH_MAX_BYTES = 2097152  # 2MB — large domains have many certs
CRTSH_USER_AGENT = "contrastscan/1.0"


# === Tech Stack / WAF Detection ===

WAF_SIGNATURES = {
    "Cloudflare": {"header": "server", "contains": "cloudflare"},
    "AWS CloudFront": {"header": "x-amz-cf-id"},
    "AWS WAF": {"header": "x-amzn-requestid"},
    "Sucuri": {"header": "x-sucuri-id"},
    "Akamai": {"header": "x-akamai-transformed"},
    "ModSecurity": {"header": "server", "contains": "mod_security"},
    "F5 BIG-IP": {"header": "server", "contains": "bigip"},
    "Imperva": {"header": "x-iinfo"},
    "Fastly": {"header": "x-served-by"},
    "Varnish": {"header": "x-varnish"},
}

COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "ftp",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "blog",
    "shop",
    "store",
    "cdn",
    "media",
    "static",
    "assets",
    "app",
    "portal",
    "dashboard",
    "cpanel",
    "webmail",
    "ns1",
    "ns2",
    "mx",
    "smtp",
    "imap",
    "pop",
    "vpn",
    "remote",
    "git",
    "ci",
]


def run_recon(scan_id: str, domain: str, scan_result: dict):
    """Background recon — called in a thread after C scan completes.

    Groups run in parallel threads for speed:
      Thread 1: robots + sitemap + http_version  (~5s)
      Thread 2: reverse_dns + zone_transfer       (~5s)
      Thread 3: crt.sh fetch                      (~30s, slow for big domains)
      Thread 4: whois                             (~5s)
    Group A (tech_stack, waf, emails) is instant — no network.
    crt.sh result feeds both subdomains and CT logs after fetch completes.
    """
    from concurrent.futures import ThreadPoolExecutor

    try:
        create_recon(scan_id, domain)
        recon = {}

        # Extract resolved IP from scan result for DNS pinning
        resolved_ip = scan_result.get("resolved_ip")

        # Group A: instant, no network
        recon["tech_stack"] = detect_tech_stack(scan_result)
        recon["waf"] = detect_waf(scan_result)
        recon["emails"] = harvest_emails(scan_result, domain)

        # Parallel groups
        def group_http():
            result = {
                "robots": fetch_robots(domain),
                "sitemap": fetch_sitemap(domain),
                "http_version": check_http_version(domain, resolved_ip),
                "security_txt": fetch_security_txt(domain),
            }
            if resolved_ip:
                result["asn"] = fetch_asn_info(resolved_ip)
            return result

        def group_dns():
            return {
                "reverse_dns": reverse_dns_lookup(domain, resolved_ip),  # PTR needs IP
                "ns_records": dns_ns_lookup(domain),
                "zone_transfer": check_zone_transfer(domain),
                "caa": check_caa(domain),
            }

        def group_crtsh_subs():
            """Wildcard query — slow for big domains, feeds subdomains."""
            return _fetch_crtsh(f"%.{domain}")

        def group_crtsh_ct():
            """Exact query — fast, feeds CT logs."""
            return _fetch_crtsh(domain)

        def group_whois():
            return {"whois": whois_lookup(domain)}

        crtsh_subs = []
        crtsh_ct = []
        with ThreadPoolExecutor(max_workers=5) as pool:
            f_http = pool.submit(group_http)
            f_dns = pool.submit(group_dns)
            f_crtsh_subs = pool.submit(group_crtsh_subs)
            f_crtsh_ct = pool.submit(group_crtsh_ct)
            f_whois = pool.submit(group_whois)

            # Fast groups — should complete in ~5s
            recon.update(f_http.result(timeout=RECON_TIMEOUT * 2))
            recon.update(f_dns.result(timeout=RECON_TIMEOUT * 2))
            recon.update(f_whois.result(timeout=RECON_TIMEOUT * 2))

            # Save partial results so frontend can render immediately
            save_recon_partial(scan_id, recon)

            # CT logs exact query — usually fast (~5s)
            try:
                crtsh_ct = f_crtsh_ct.result(timeout=RECON_TIMEOUT * 3)
            except Exception:
                crtsh_ct = []

            # Subdomain wildcard — may take longer
            try:
                crtsh_subs = f_crtsh_subs.result(timeout=RECON_TIMEOUT * 3)
            except Exception:
                crtsh_subs = []
                logger.warning("crt.sh subdomain timeout for %s", domain)

        recon["subdomains"] = enumerate_subdomains(domain, crtsh_subs)
        recon["ct_logs"] = check_ct_logs(domain, crtsh_ct)

        # Subdomain takeover check (runs after subdomains are enumerated)
        subs = recon["subdomains"].get("subdomains", [])
        if subs:
            recon["subdomain_takeover"] = check_subdomain_takeover(subs)
        else:
            recon["subdomain_takeover"] = {"vulnerable": [], "checked": 0, "cname_count": 0}

        save_recon(scan_id, recon)
        logger.info("Recon complete: %s (%s)", domain, scan_id[:8])
    except RuntimeError as e:
        logger.warning("Recon interrupted by shutdown: %s — %s", domain, str(e))
    except Exception as e:
        logger.error("Recon failed: %s — %s", domain, str(e))
        save_recon_error(scan_id, str(e))


_recon_semaphore = threading.Semaphore(10)  # max 10 concurrent recon threads


def start_recon(scan_id: str, domain: str, scan_result: dict):
    """Launch recon in background thread (bounded to 10 concurrent)."""

    def _bounded_recon():
        if _recon_semaphore.acquire(timeout=30):
            try:
                run_recon(scan_id, domain, scan_result)
            finally:
                _recon_semaphore.release()
        else:
            logger.warning("Recon skipped (semaphore full): %s", domain)

    t = threading.Thread(target=_bounded_recon, daemon=True)
    t.start()


# === Group A: From existing scan data ===


def detect_tech_stack(scan_result: dict) -> dict:
    detected = []
    # We don't have raw HTML in Python — check what C scanner found
    # Use disclosure headers for server/powered-by
    disc = scan_result.get("disclosure", {}).get("details", {})
    if disc.get("server_value"):
        detected.append({"name": disc["server_value"], "source": "server_header"})
    if disc.get("powered_by_value"):
        detected.append({"name": disc["powered_by_value"], "source": "x-powered-by"})
    # Check CSP for known CDN patterns
    csp = scan_result.get("csp_analysis", {}).get("details", {})
    if csp.get("csp_present"):
        detected.append({"name": "CSP enabled", "source": "headers"})
    return {"technologies": detected, "count": len(detected)}


def detect_waf(scan_result: dict) -> dict:
    disc = scan_result.get("disclosure", {}).get("details", {})
    server = (disc.get("server_value") or "").lower()
    detected = []
    for waf_name, sig in WAF_SIGNATURES.items():
        if "contains" in sig:
            if sig["contains"] in server:
                detected.append(waf_name)
        # Header-only checks would need raw headers — use server value
    return {"detected": detected, "waf_present": len(detected) > 0}


def harvest_emails(scan_result: dict, domain: str) -> dict:
    # Strip www. for email guessing — info@www.example.com is wrong
    email_domain = domain
    if email_domain.startswith("www."):
        email_domain = email_domain[4:]
    # Check DNS for MX
    emails = []
    try:
        mx_records = dns.resolver.resolve(email_domain, "MX", lifetime=RECON_TIMEOUT)
        for mx in mx_records:
            host = str(mx.exchange).rstrip(".")
            emails.append(f"MX: {mx.preference} {host}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    # Common email patterns
    common = [f"info@{email_domain}", f"admin@{email_domain}", f"contact@{email_domain}"]
    return {"found": emails, "common_guesses": common}


# === Group B: Simple HTTP ===


def fetch_security_txt(domain: str) -> dict:
    """Fetch /.well-known/security.txt and parse RFC 9116 fields."""
    try:
        req = Request(f"https://{domain}/.well-known/security.txt", headers={"User-Agent": "contrastscan/1.0"})
        resp = _no_redirect_opener.open(req, timeout=3)
        text = resp.read(8192).decode("utf-8", errors="ignore")
        if not text.strip():
            return {"found": False}
        fields = {}
        parse_keys = {
            "contact": "contact",
            "expires": "expires",
            "encryption": "encryption",
            "acknowledgments": "acknowledgments",
            "preferred-languages": "preferred_languages",
            "canonical": "canonical",
            "policy": "policy",
        }
        for line in text.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                key_lower = key.strip().lower()
                if key_lower in parse_keys:
                    field_name = parse_keys[key_lower]
                    val = value.strip()
                    # Some fields can appear multiple times (Contact)
                    if field_name in fields:
                        if isinstance(fields[field_name], list):
                            fields[field_name].append(val)
                        else:
                            fields[field_name] = [fields[field_name], val]
                    else:
                        fields[field_name] = val
        return {"found": True, "fields": fields, "raw": text[:2000]}
    except Exception:
        return {"found": False}


def check_caa(domain: str) -> dict:
    """Query CAA DNS records — which CAs are allowed to issue certificates."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "CAA")
        records = []
        issuers = []
        for rdata in answers:
            record = {
                "flags": rdata.flags,
                "tag": rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag),
                "value": rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value),
            }
            records.append(record)
            if record["tag"] in ("issue", "issuewild"):
                issuer = record["value"].strip().rstrip(".")
                if issuer and issuer not in issuers:
                    issuers.append(issuer)
        return {"found": True, "records": records, "issuers": issuers}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return {"found": False, "records": [], "issuers": []}
    except Exception:
        return {"found": False, "records": [], "issuers": []}


def fetch_asn_info(ip: str) -> dict:
    """Look up ASN, org name, and announced prefixes from RIPE Stat."""
    import ipaddress

    if is_private_ip(ip):
        return {"asn": None, "error": "Cannot query ASN for private IP"}

    try:
        # Step 1: Get ASN from IP
        req = Request(
            f"https://stat.ripe.net/data/network-info/data.json?resource={ip}",
            headers={"User-Agent": "contrastscan/1.0"},
        )
        resp = _no_redirect_opener.open(req, timeout=5)
        data = json.loads(resp.read(32768))
        asns = data.get("data", {}).get("asns", [])
        if not asns or not asns[0]:
            return {"asn": None, "error": "No ASN found"}
        asn = int(asns[0])

        # Step 2: Get ASN holder name
        asn_name = ""
        try:
            req2 = Request(
                f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}",
                headers={"User-Agent": "contrastscan/1.0"},
            )
            resp2 = _no_redirect_opener.open(req2, timeout=5)
            data2 = json.loads(resp2.read(32768))
            asn_name = data2.get("data", {}).get("holder", "")
        except Exception:
            pass

        # Step 3: Get announced prefixes
        ipv4_prefixes = []
        ipv6_prefixes = []
        try:
            req3 = Request(
                f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}",
                headers={"User-Agent": "contrastscan/1.0"},
            )
            resp3 = _no_redirect_opener.open(req3, timeout=5)
            data3 = json.loads(resp3.read(131072))
            for p in data3.get("data", {}).get("prefixes", []):
                prefix = p.get("prefix", "")
                if not prefix:
                    continue
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                    if net.version == 4:
                        ipv4_prefixes.append({"prefix": prefix})
                    else:
                        ipv6_prefixes.append({"prefix": prefix})
                except ValueError:
                    continue
        except Exception:
            pass

        return {
            "asn": asn,
            "asn_name": asn_name,
            "ipv4_prefixes": ipv4_prefixes[:50],
            "ipv6_prefixes": ipv6_prefixes[:20],
            "ipv4_count": len(ipv4_prefixes),
            "ipv6_count": len(ipv6_prefixes),
        }
    except Exception as e:
        logger.warning("ASN lookup failed for %s: %s", ip, e)
        return {"asn": None, "error": "ASN lookup failed"}


def fetch_robots(domain: str) -> dict:
    # Connect by domain name — IP causes SSL cert mismatch on HTTPS.
    # DNS rebinding mitigated by _no_redirect_opener blocking redirects.
    try:
        req = Request(f"https://{domain}/robots.txt", headers={"User-Agent": "contrastscan/1.0"})
        resp = _no_redirect_opener.open(req, timeout=RECON_TIMEOUT)
        text = resp.read(32768).decode("utf-8", errors="ignore")
        lines = text.strip().split("\n")
        disallowed = [
            line.split(":", 1)[1].strip()
            for line in lines
            if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()
        ]
        sitemaps = [line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("sitemap:")]
        return {
            "exists": True,
            "disallowed_paths": disallowed[:20],
            "sitemaps": sitemaps[:5],
            "line_count": len(lines),
        }
    except Exception:
        return {"exists": False}


def fetch_sitemap(domain: str) -> dict:
    try:
        req = Request(f"https://{domain}/sitemap.xml", headers={"User-Agent": "contrastscan/1.0"})
        resp = _no_redirect_opener.open(req, timeout=RECON_TIMEOUT)
        text = resp.read(65536).decode("utf-8", errors="ignore")
        urls = re.findall(r"<loc>(.*?)</loc>", text)
        return {
            "exists": True,
            "url_count": len(urls),
            "sample_urls": urls[:10],
        }
    except Exception:
        return {"exists": False}


def check_http_version(domain: str, resolved_ip: str | None = None) -> dict:
    result = {"http2": False, "http3": False}
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        connect_target = resolved_ip if resolved_ip else domain
        with socket.create_connection((connect_target, 443), timeout=RECON_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                proto = ssock.selected_alpn_protocol()
                result["http2"] = proto == "h2"
                result["negotiated"] = proto or "http/1.1"
    except Exception:
        result["negotiated"] = "unknown"
    return result


# === Group C: DNS ===


def reverse_dns_lookup(domain: str, resolved_ip: str | None = None) -> dict:
    try:
        # Resolve both IPv4 and IPv6
        ipv4, ipv6 = None, None
        try:
            for info in socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM):
                ipv4 = info[4][0]
                break
        except socket.gaierror:
            pass
        try:
            for info in socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM):
                addr = info[4][0]
                if not addr.startswith("::ffff:"):  # skip mapped IPv4
                    ipv6 = addr
                    break
        except socket.gaierror:
            pass

        ip = resolved_ip or ipv4 or ipv6
        ptr = None
        if ip:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                ptr = hostname
            except socket.herror:
                pass

        result = {"ip": ip, "ptr": ptr}
        if ip and ptr:
            result["shared_hosting"] = ptr != domain
        if ipv4:
            result["ipv4"] = ipv4
        if ipv6:
            result["ipv6"] = ipv6
        return result
    except Exception:
        return {"ip": None, "ptr": None}


def dns_ns_lookup(domain: str) -> dict:
    """Resolve NS records for domain, including each nameserver's IP."""
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=RECON_TIMEOUT)
        records = []
        ns_resolver = dns.resolver.Resolver()
        ns_resolver.lifetime = 2
        for rdata in answers:
            hostname = str(rdata.target).rstrip(".")
            ip = None
            try:
                a_answers = ns_resolver.resolve(hostname, "A")
                ip = str(a_answers[0])
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            records.append({"hostname": hostname, "ip": ip})
        return {"ns_records": records, "count": len(records)}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return {"ns_records": [], "count": 0}
    except Exception as e:
        logger.warning("Unexpected error in dns_ns_lookup for %s: %s", domain, e)
        return {"ns_records": [], "count": 0}


def check_zone_transfer(domain: str) -> dict:
    """Check if AXFR zone transfer is possible (security risk if open)."""
    try:
        # Get nameservers
        result = subprocess.run(["dig", "+short", "NS", domain], capture_output=True, text=True, timeout=RECON_TIMEOUT)
        ns_pattern = re.compile(r"^[a-zA-Z0-9.-]+$")
        nameservers = [
            ns.strip().rstrip(".")
            for ns in result.stdout.strip().split("\n")
            if ns.strip() and ns_pattern.match(ns.strip().rstrip("."))
        ]
        if not nameservers:
            return {"vulnerable": False, "nameservers": []}

        # Try AXFR on first nameserver
        for ns in nameservers[:2]:
            try:
                axfr = subprocess.run(
                    ["dig", f"@{ns}", domain, "AXFR", "+short"], capture_output=True, text=True, timeout=RECON_TIMEOUT
                )
                if axfr.stdout.strip() and "Transfer failed" not in axfr.stdout:
                    records = [rec for rec in axfr.stdout.strip().split("\n") if rec.strip()]
                    if len(records) > 2:
                        return {
                            "vulnerable": True,
                            "nameserver": ns,
                            "record_count": len(records),
                        }
            except Exception:
                continue

        return {"vulnerable": False, "nameservers": nameservers[:5]}
    except Exception:
        return {"vulnerable": False, "error": "check failed"}


def enumerate_subdomains(domain: str, crtsh_data: list | None = None) -> dict:
    found = []

    # Method 1: DNS brute force common subdomains (skip private IPs — SSRF defense)
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            results = socket.getaddrinfo(fqdn, None, type=socket.SOCK_STREAM)
            # Check ALL resolved IPs (IPv4 + IPv6) for private addresses
            all_public = results and all(not is_private_ip(sa[0]) for _, _, _, _, sa in results)
            if all_public:
                found.append(fqdn)
        except socket.gaierror:
            pass

    # Method 2: crt.sh certificate transparency (use cached data if available)
    ct_subs = _crtsh_subdomains(domain, crtsh_data)
    for s in ct_subs:
        if s not in found:
            found.append(s)

    return {"subdomains": sorted(set(found)), "count": len(set(found))}


def _fetch_crtsh(query: str) -> list:
    try:
        from urllib.parse import quote

        req = Request(
            f"https://crt.sh/?q={quote(query, safe='%.')}&output=json", headers={"User-Agent": CRTSH_USER_AGENT}
        )
        with _no_redirect_opener.open(req, timeout=CRTSH_TIMEOUT) as resp:
            return json.loads(resp.read(CRTSH_MAX_BYTES))
    except Exception:
        return []


def _crtsh_subdomains(domain: str, data: list | None = None) -> list:
    if data is None:
        data = _fetch_crtsh(f"%.{domain}")
    subs = set()
    for entry in data:
        name = entry.get("name_value", "")
        for n in name.split("\n"):
            n = n.strip().lower()
            if n.endswith(f".{domain}") and "*" not in n:
                subs.add(n)
    return sorted(subs)[:50]


# === Group D: External ===


def whois_lookup(domain: str) -> dict:
    """Raw WHOIS query via port 43."""
    try:
        # Determine WHOIS server
        parts = domain.split(".")
        tld = parts[-1]
        # Check for compound TLDs (co.uk, com.tr, etc.)
        tld2 = ".".join(parts[-2:]) if len(parts) >= 2 else tld
        whois_servers = {
            # Generic TLDs
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "io": "whois.nic.io",
            # .dev and .app use RDAP only (no port 43 WHOIS)
            "dev": None,
            "app": None,
            "xyz": "whois.nic.xyz",
            "info": "whois.afilias.net",
            "me": "whois.nic.me",
            # Country-code TLDs
            "tr": "whois.trabis.gov.tr",
            "de": "whois.denic.de",
            "uk": "whois.nic.uk",
            "fr": "whois.nic.fr",
            "nl": "whois.sidn.nl",
            "ru": "whois.tcinet.ru",
            "br": "whois.registro.br",
            "au": "whois.auda.org.au",
            "jp": "whois.jprs.jp",
            "kr": "whois.kr",
            "cn": "whois.cnnic.cn",
            "in": "whois.registry.in",
        }
        # Try compound TLD first (co.uk), then simple TLD
        server = whois_servers.get(tld2, whois_servers.get(tld, f"whois.nic.{tld}"))
        if server is None:
            return {"error": f"No WHOIS server for .{tld} (RDAP only)"}

        # Validate WHOIS server doesn't resolve to private IP
        try:
            server_ip = socket.gethostbyname(server)
            if is_private_ip(server_ip):
                return {"error": f"WHOIS server {server} resolved to private IP"}
        except socket.gaierror:
            return {"error": f"Cannot resolve WHOIS server {server}"}

        with socket.create_connection((server_ip, 43), timeout=RECON_TIMEOUT) as sock:
            sock.settimeout(RECON_TIMEOUT)
            sock.sendall(f"{domain}\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 32768:
                    break

        text = response.decode("utf-8", errors="ignore")
        info = _parse_whois(text)
        info["raw_length"] = len(text)
        return info
    except Exception as e:
        return {"error": str(e)}


def _parse_whois(text: str) -> dict:
    result = {}
    patterns = {
        "registrar": r"(?:Registrar|Registrant):\s*(.+)",
        "creation_date": r"(?:Creat(?:ion|ed)\s*Date|Registered\s*on|Registration\s*Date):\s*(.+)",
        "expiry_date": r"(?:Expir(?:y|ation)\s*Date|Registry Expiry Date|Expiry\s*date|Renewal\s*date):\s*(.+)",
        "updated_date": r"(?:Updated\s*Date|Last\s*updated):\s*(.+)",
        "name_servers": r"(?:Name\s*Server|Name\s*servers):\s*(.+)",
        "status": r"(?:Domain\s*)?Status:\s*(.+)",
    }
    for key, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            if key == "name_servers":
                result[key] = [m.strip().lower() for m in matches[:4]]
            elif key == "status":
                result[key] = [m.strip() for m in matches[:5]]
            else:
                result[key] = matches[0].strip()
    return result


# === Subdomain Takeover Detection ===

TAKEOVER_FINGERPRINTS = [
    {"service": "GitHub Pages", "cname": r"\.github\.io$", "fingerprint": "There isn't a GitHub Pages site here"},
    {"service": "Heroku", "cname": r"\.herokuapp\.com$", "fingerprint": "No such app"},
    {"service": "AWS S3", "cname": r"\.s3[.-].*\.amazonaws\.com$", "fingerprint": "NoSuchBucket"},
    {"service": "AWS Elastic Beanstalk", "cname": r"\.elasticbeanstalk\.com$", "fingerprint": None},
    {"service": "Azure App Service", "cname": r"\.azurewebsites\.net$", "fingerprint": "Web app not found"},
    {"service": "Azure Traffic Manager", "cname": r"\.trafficmanager\.net$", "fingerprint": None},
    {"service": "Azure CDN", "cname": r"\.azureedge\.net$", "fingerprint": None},
    {"service": "Azure Blob", "cname": r"\.blob\.core\.windows\.net$", "fingerprint": "BlobNotFound"},
    {"service": "Shopify", "cname": r"\.myshopify\.com$", "fingerprint": "Sorry, this shop is currently unavailable"},
    {"service": "Tumblr", "cname": r"\.tumblr\.com$", "fingerprint": "There's nothing here"},
    {"service": "WordPress.com", "cname": r"\.wordpress\.com$", "fingerprint": "doesn't exist"},
    {"service": "Fastly", "cname": r"\.fastly\.net$", "fingerprint": "Fastly error: unknown domain"},
    {"service": "Pantheon", "cname": r"\.pantheonsite\.io$", "fingerprint": "404 error unknown site"},
    {"service": "Surge.sh", "cname": r"\.surge\.sh$", "fingerprint": "project not found"},
    {"service": "Fly.io", "cname": r"\.fly\.dev$", "fingerprint": None},
    {"service": "Netlify", "cname": r"\.netlify\.app$", "fingerprint": "Not found - Request ID"},
    {"service": "Vercel", "cname": r"cname\.vercel-dns\.com$", "fingerprint": "deployment could not be found"},
    {"service": "Zendesk", "cname": r"\.zendesk\.com$", "fingerprint": "Help Center Closed"},
    {"service": "HubSpot", "cname": r"\.hubspot\.net$", "fingerprint": "Domain not found"},
    {"service": "Ghost", "cname": r"\.ghost\.io$", "fingerprint": "no longer here"},
    {"service": "Tilda", "cname": r"\.tilda\.ws$", "fingerprint": "Please renew your subscription"},
    {"service": "Unbounce", "cname": r"\.unbouncepages\.com$", "fingerprint": "The requested URL was not found"},
    {"service": "Strikingly", "cname": r"\.strikinglydns\.com$", "fingerprint": "page not found"},
    {"service": "Cargo", "cname": r"cname\.cargo\.site$", "fingerprint": None},
    {"service": "Campaign Monitor", "cname": r"\.createsend\.com$", "fingerprint": None},
    {"service": "Readme.io", "cname": r"\.readme\.io$", "fingerprint": "Project doesnt exist"},
    {"service": "Help Scout", "cname": r"\.helpscoutdocs\.com$", "fingerprint": "No settings were found"},
    {"service": "Agile CRM", "cname": r"\.agilecrm\.com$", "fingerprint": "no longer available"},
    {"service": "Bitbucket", "cname": r"\.bitbucket\.io$", "fingerprint": "Repository not found"},
    {"service": "Smartling", "cname": r"\.smartling\.com$", "fingerprint": None},
]

TAKEOVER_MAX_SUBS = 100
TAKEOVER_HTTP_TIMEOUT = 3
TAKEOVER_MAX_BODY = 8192


def check_subdomain_takeover(subdomains: list[str]) -> dict:
    """Check discovered subdomains for dangling CNAME records (takeover risk)."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    vulnerable = []
    cname_count = 0
    cname_lock = threading.Lock()
    checked = min(len(subdomains), TAKEOVER_MAX_SUBS)

    def _check_one(subdomain: str) -> dict | None:
        nonlocal cname_count
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            answers = resolver.resolve(subdomain, "CNAME")
            cname_target = str(answers[0].target).rstrip(".").lower()
            with cname_lock:
                cname_count += 1
        except Exception:
            return None

        # Check if CNAME target resolves (retry once to avoid transient DNS failures)
        nxdomain = False
        for _attempt in range(2):
            try:
                socket.gethostbyname(cname_target)
                nxdomain = False
                break
            except socket.gaierror:
                nxdomain = True
                if _attempt == 0:
                    import time

                    time.sleep(0.5)

        # Match against known vulnerable services
        matched_service = None
        matched_fingerprint = None
        for fp in TAKEOVER_FINGERPRINTS:
            if re.search(fp["cname"], cname_target, re.IGNORECASE):
                matched_service = fp["service"]
                matched_fingerprint = fp["fingerprint"]
                break

        if nxdomain and matched_service:
            return {
                "subdomain": subdomain,
                "cname": cname_target,
                "service": matched_service,
                "evidence": "NXDOMAIN — CNAME target does not resolve",
                "severity": "high",
            }

        if nxdomain:
            return {
                "subdomain": subdomain,
                "cname": cname_target,
                "service": "unknown",
                "evidence": "NXDOMAIN — dangling CNAME",
                "severity": "medium",
            }

        # CNAME resolves but check HTTP fingerprint for known services
        if matched_service and matched_fingerprint:
            try:
                # Resolve and check for private IP, then use resolved IP to prevent TOCTOU
                try:
                    sub_ip = socket.gethostbyname(subdomain)
                    if is_private_ip(sub_ip):
                        return None
                except socket.gaierror:
                    return None
                req = Request(f"http://{sub_ip}/", headers={"User-Agent": "contrastscan/1.0", "Host": subdomain})
                with _no_redirect_opener.open(req, timeout=TAKEOVER_HTTP_TIMEOUT) as resp:
                    body = resp.read(TAKEOVER_MAX_BODY).decode("utf-8", errors="ignore")
                    if matched_fingerprint.lower() in body.lower():
                        return {
                            "subdomain": subdomain,
                            "cname": cname_target,
                            "service": matched_service,
                            "evidence": f'HTTP fingerprint: "{matched_fingerprint}"',
                            "severity": "high",
                        }
            except Exception:
                pass

        return None

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(_check_one, sub) for sub in subdomains[:TAKEOVER_MAX_SUBS]]
        for fut in futures:
            try:
                result = fut.result(timeout=10)
                if result:
                    vulnerable.append(result)
            except Exception:
                pass

    return {
        "vulnerable": vulnerable,
        "checked": checked,
        "cname_count": cname_count,
    }


CT_MAX_ENTRIES = 20
CT_MAX_CERTS = 10


def check_ct_logs(domain: str, crtsh_data: list | None = None) -> dict:
    """Query crt.sh for certificate transparency logs."""
    try:
        data = crtsh_data if crtsh_data is not None else _fetch_crtsh(domain)
        if not data:
            return {"total_certificates": 0, "error": "crt.sh query failed"}

        certs = []
        seen: set[str] = set()
        for entry in data[:CT_MAX_ENTRIES]:
            serial = entry.get("serial_number", "")
            if serial in seen:
                continue
            seen.add(serial)
            certs.append(
                {
                    "issuer": entry.get("issuer_name", ""),
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                    "common_name": entry.get("common_name", ""),
                }
            )

        return {
            "total_certificates": len(data),
            "recent_certificates": certs[:CT_MAX_CERTS],
        }
    except Exception:
        return {"total_certificates": 0, "error": "crt.sh query failed"}
