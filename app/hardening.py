"""Server hardening recommendations based on scan results.

Generates actionable fix commands and ASCII diagrams for monitoring reports.
Each recommendation includes: category, priority, description, fix commands,
and optional ASCII diagram showing the attack/defense flow.
"""

# Priority levels: critical > high > medium > low
# Only findings that map to server-side fixes get recommendations.
# Client-side-only issues (inline scripts, SRI) are excluded.

_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _ssl_recommendations(result: dict) -> list[dict]:
    """TLS/SSL hardening: protocol version, cipher, cert renewal."""
    recs = []
    ssl = result.get("ssl", {})
    details = ssl.get("details", {})

    if ssl.get("error"):
        recs.append({
            "category": "SSL/TLS",
            "priority": "critical",
            "title": "Install SSL Certificate",
            "description": "No valid TLS connection. Site is served over plain HTTP.",
            "commands": {
                "nginx": [
                    "# Install certbot and obtain certificate",
                    "apt install -y certbot python3-certbot-nginx",
                    "certbot --nginx -d example.com -d www.example.com",
                    "",
                    "# Auto-renew (cron)",
                    "echo '0 3 * * * certbot renew --quiet' | crontab -",
                ],
                "apache": [
                    "apt install -y certbot python3-certbot-apache",
                    "certbot --apache -d example.com -d www.example.com",
                ],
            },
            "diagram": (
                "  Client          Server\n"
                "    |--- HTTP -------->|  Plain text!\n"
                "    |   (password)     |  Attacker can read\n"
                "    |                  |  everything.\n"
                "    |                  |\n"
                "  After fix:\n"
                "    |--- TLS 1.3 ---->|  Encrypted\n"
                "    |   [encrypted]   |  MITM blocked\n"
            ),
        })
        return recs

    tls_ver = details.get("tls_version", "")
    if tls_ver in ("TLSv1", "TLSv1.1"):
        recs.append({
            "category": "SSL/TLS",
            "priority": "high",
            "title": "Disable Deprecated TLS Versions",
            "description": f"{tls_ver} is vulnerable to BEAST/POODLE attacks.",
            "commands": {
                "nginx": [
                    "# /etc/nginx/nginx.conf (or site config)",
                    "ssl_protocols TLSv1.2 TLSv1.3;",
                    "ssl_prefer_server_ciphers on;",
                ],
                "apache": [
                    "# /etc/apache2/mods-enabled/ssl.conf",
                    "SSLProtocol -all +TLSv1.2 +TLSv1.3",
                ],
            },
        })
    elif tls_ver == "TLSv1.2":
        recs.append({
            "category": "SSL/TLS",
            "priority": "low",
            "title": "Enable TLS 1.3",
            "description": "TLS 1.2 is secure but TLS 1.3 is faster and stronger.",
            "commands": {
                "nginx": [
                    "ssl_protocols TLSv1.2 TLSv1.3;",
                ],
            },
        })

    cipher_score = details.get("cipher_score", 6)
    if cipher_score <= 3:
        recs.append({
            "category": "SSL/TLS",
            "priority": "medium",
            "title": "Upgrade Cipher Suites",
            "description": f"Weak cipher: {details.get('cipher', 'unknown')}.",
            "commands": {
                "nginx": [
                    "# Mozilla Intermediate config",
                    "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';",
                    "ssl_prefer_server_ciphers off;",
                ],
            },
        })

    days = details.get("days_remaining", 365)
    if 0 < days <= 30:
        recs.append({
            "category": "SSL/TLS",
            "priority": "high",
            "title": "Renew SSL Certificate",
            "description": f"Certificate expires in {days} days.",
            "commands": {
                "nginx": [
                    "certbot renew --quiet",
                    "systemctl reload nginx",
                ],
            },
        })
    elif days <= 0:
        recs.append({
            "category": "SSL/TLS",
            "priority": "critical",
            "title": "SSL Certificate Expired",
            "description": "Certificate has expired. Browsers will show security warnings.",
            "commands": {
                "nginx": [
                    "certbot renew --force-renewal",
                    "systemctl reload nginx",
                ],
            },
        })

    return recs


def _header_recommendations(result: dict) -> list[dict]:
    """Security header hardening with nginx/Apache snippets."""
    recs = []
    headers = result.get("headers", {})
    details = headers.get("details", [])
    if not isinstance(details, list):
        return recs

    missing = [h["header"] for h in details if not h.get("present")]
    if not missing:
        return recs

    # Map header name to nginx config line
    header_configs = {
        "strict-transport-security": {
            "nginx": "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;",
            "apache": 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
            "priority": "high",
        },
        "content-security-policy": {
            "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';\" always;",
            "apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'\"",
            "priority": "high",
        },
        "x-content-type-options": {
            "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "apache": 'Header always set X-Content-Type-Options "nosniff"',
            "priority": "medium",
        },
        "x-frame-options": {
            "nginx": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
            "apache": 'Header always set X-Frame-Options "SAMEORIGIN"',
            "priority": "medium",
        },
        "referrer-policy": {
            "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            "priority": "low",
        },
        "permissions-policy": {
            "nginx": "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;",
            "apache": 'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
            "priority": "low",
        },
    }

    nginx_lines = ["# /etc/nginx/snippets/security-headers.conf"]
    apache_lines = ["# /etc/apache2/conf-available/security-headers.conf"]
    top_priority = "low"

    for h in missing:
        cfg = header_configs.get(h)
        if cfg:
            nginx_lines.append(cfg["nginx"])
            apache_lines.append(cfg["apache"])
            if _PRIORITY_ORDER.get(cfg["priority"], 3) < _PRIORITY_ORDER.get(top_priority, 3):
                top_priority = cfg["priority"]

    nginx_lines.extend([
        "",
        "# Include in your server block:",
        "# include snippets/security-headers.conf;",
        "systemctl reload nginx",
    ])
    apache_lines.extend([
        "",
        "a2enmod headers",
        "a2enconf security-headers",
        "systemctl reload apache2",
    ])

    recs.append({
        "category": "Security Headers",
        "priority": top_priority,
        "title": f"Add Missing Security Headers ({len(missing)})",
        "description": f"Missing: {', '.join(missing)}.",
        "commands": {
            "nginx": nginx_lines,
            "apache": apache_lines,
        },
        "diagram": (
            "  Browser         Server\n"
            "    |--- GET / ------->|\n"
            "    |<-- 200 OK -------|\n"
            "    |   (no headers)   |  XSS, clickjack,\n"
            "    |                  |  MIME sniff possible\n"
            "    |                  |\n"
            "  After fix:\n"
            "    |<-- 200 OK -------|\n"
            "    |   +HSTS +CSP    |  Browser enforces\n"
            "    |   +X-Frame-Opt  |  security policies\n"
        ),
    })

    return recs


def _redirect_recommendations(result: dict) -> list[dict]:
    """HTTP to HTTPS redirect."""
    redirect = result.get("redirect", {}).get("details", {})
    if redirect.get("redirects_to_https"):
        return []

    return [{
        "category": "HTTP Redirect",
        "priority": "high",
        "title": "Enable HTTP to HTTPS Redirect",
        "description": "HTTP traffic is not redirected to HTTPS.",
        "commands": {
            "nginx": [
                "# /etc/nginx/sites-available/example.com",
                "server {",
                "    listen 80;",
                "    server_name example.com www.example.com;",
                "    return 301 https://$host$request_uri;",
                "}",
                "systemctl reload nginx",
            ],
            "apache": [
                "# /etc/apache2/sites-available/example.com.conf",
                "<VirtualHost *:80>",
                "    ServerName example.com",
                "    Redirect permanent / https://example.com/",
                "</VirtualHost>",
                "a2enmod rewrite",
                "systemctl reload apache2",
            ],
        },
    }]


def _disclosure_recommendations(result: dict) -> list[dict]:
    """Server version disclosure hiding."""
    recs = []
    disc = result.get("disclosure", {}).get("details", {})

    if disc.get("server_exposed") or disc.get("powered_by_exposed"):
        recs.append({
            "category": "Info Disclosure",
            "priority": "medium",
            "title": "Hide Server Version Information",
            "description": "Server software and version are exposed in response headers.",
            "commands": {
                "nginx": [
                    "# /etc/nginx/nginx.conf (http block)",
                    "server_tokens off;",
                    "# Remove X-Powered-By (if proxying PHP/Node)",
                    "proxy_hide_header X-Powered-By;",
                    "fastcgi_hide_header X-Powered-By;",
                    "systemctl reload nginx",
                ],
                "apache": [
                    "# /etc/apache2/conf-enabled/security.conf",
                    "ServerTokens Prod",
                    "ServerSignature Off",
                    "Header unset X-Powered-By",
                    "systemctl reload apache2",
                ],
            },
        })

    return recs


def _methods_recommendations(result: dict) -> list[dict]:
    """Dangerous HTTP methods restriction."""
    details = result.get("methods", {}).get("details", {})
    dangerous = []
    if details.get("trace_enabled"):
        dangerous.append("TRACE")
    if details.get("delete_enabled"):
        dangerous.append("DELETE")
    if details.get("put_enabled"):
        dangerous.append("PUT")

    if not dangerous:
        return []

    return [{
        "category": "HTTP Methods",
        "priority": "high" if "TRACE" in dangerous else "medium",
        "title": f"Disable Dangerous HTTP Methods ({', '.join(dangerous)})",
        "description": f"Methods {', '.join(dangerous)} are enabled and exploitable.",
        "commands": {
            "nginx": [
                "# In your server block:",
                "if ($request_method !~ ^(GET|HEAD|POST)$ ) {",
                "    return 444;",
                "}",
                "systemctl reload nginx",
            ],
            "apache": [
                "# /etc/apache2/sites-available/example.com.conf",
                "<Location />",
                '    <LimitExcept GET HEAD POST>',
                "        Require all denied",
                "    </LimitExcept>",
                "</Location>",
                "systemctl reload apache2",
            ],
        },
    }]


def _dns_recommendations(result: dict) -> list[dict]:
    """Email security DNS records."""
    recs = []
    dns = result.get("dns", {}).get("details", {})

    missing_records = []
    if not dns.get("spf"):
        missing_records.append("SPF")
    if not dns.get("dmarc"):
        missing_records.append("DMARC")
    if not dns.get("dkim"):
        missing_records.append("DKIM")

    if not missing_records:
        return recs

    commands = []
    if "SPF" in missing_records:
        commands.extend([
            "# SPF — Add TXT record to DNS:",
            "# example.com  TXT  \"v=spf1 include:_spf.google.com -all\"",
            "",
        ])
    if "DMARC" in missing_records:
        commands.extend([
            "# DMARC — Add TXT record to DNS:",
            "# _dmarc.example.com  TXT  \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com\"",
            "",
        ])
    if "DKIM" in missing_records:
        commands.extend([
            "# DKIM — Generate key pair and publish:",
            "# Configure in your email provider (Google Workspace, Postfix, etc.)",
            "# Publish the public key as a TXT record at selector._domainkey.example.com",
        ])

    recs.append({
        "category": "DNS Security",
        "priority": "high",
        "title": f"Add Missing Email Security Records ({', '.join(missing_records)})",
        "description": "Domain is vulnerable to email spoofing/phishing.",
        "commands": {
            "dns": commands,
        },
        "diagram": (
            "  Attacker        Victim Inbox\n"
            "    |--- SMTP -------->|\n"
            "    | From: ceo@domain |  No SPF/DMARC?\n"
            "    |                  |  Email accepted!\n"
            "    |                  |\n"
            "  After fix:\n"
            "    |--- SMTP -------->|\n"
            "    | From: ceo@domain |  SPF fail +\n"
            "    |            [REJECT]  DMARC p=reject\n"
        ),
    })

    return recs


def _cookie_recommendations(result: dict) -> list[dict]:
    """Cookie security flags."""
    details = result.get("cookies", {}).get("details", {})
    if details.get("cookies_found", 0) == 0:
        return []

    missing = []
    if not details.get("all_secure"):
        missing.append("Secure")
    if not details.get("all_httponly"):
        missing.append("HttpOnly")
    if not details.get("all_samesite"):
        missing.append("SameSite")

    if not missing:
        return []

    return [{
        "category": "Cookie Security",
        "priority": "medium",
        "title": f"Add Missing Cookie Flags ({', '.join(missing)})",
        "description": "Cookies are missing security attributes.",
        "commands": {
            "nginx": [
                "# If using proxy_cookie_path:",
                'proxy_cookie_flags ~ secure httponly samesite=lax;',
                "",
                "# Or in application code (Python/Node/PHP):",
                "# Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax",
            ],
            "apache": [
                "# /etc/apache2/conf-enabled/security.conf",
                "Header edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly; SameSite=Lax\"",
                "systemctl reload apache2",
            ],
        },
    }]


def _cors_recommendations(result: dict) -> list[dict]:
    """CORS misconfiguration fix."""
    details = result.get("cors", {}).get("details", {})

    if details.get("credentials_with_wildcard") or details.get("reflects_origin"):
        return [{
            "category": "CORS",
            "priority": "critical" if details.get("credentials_with_wildcard") else "high",
            "title": "Fix CORS Misconfiguration",
            "description": "CORS allows credentials from any origin — full account takeover possible.",
            "commands": {
                "nginx": [
                    "# NEVER reflect Origin blindly. Whitelist specific domains:",
                    "set $cors_origin '';",
                    "if ($http_origin ~* '^https://(app\\.example\\.com|admin\\.example\\.com)$') {",
                    "    set $cors_origin $http_origin;",
                    "}",
                    "add_header Access-Control-Allow-Origin $cors_origin always;",
                    "add_header Access-Control-Allow-Credentials true always;",
                    "systemctl reload nginx",
                ],
            },
            "diagram": (
                "  evil.com         Your Server      User\n"
                "    |--- fetch() ----->|               |\n"
                "    | Origin: evil.com |               |\n"
                "    |<-- ACAO: * ------|               |\n"
                "    |   + credentials  |               |\n"
                "    |   [STEAL DATA]   |               |\n"
                "    |                  |               |\n"
                "  After fix:\n"
                "    |--- fetch() ----->|               |\n"
                "    |<-- 403 ----------|  Origin not   |\n"
                "    |   [BLOCKED]      |  whitelisted  |\n"
            ),
        }]

    return []


def _kernel_recommendations(result: dict) -> list[dict]:
    """General kernel/OS hardening — always included in monitoring reports."""
    score = result.get("total_score", 100)
    grade = result.get("grade", "A")

    # Only suggest kernel hardening for sites scoring C or below
    if grade in ("A", "B"):
        return []

    return [{
        "category": "Kernel Hardening",
        "priority": "medium",
        "title": "Apply Kernel Security Parameters",
        "description": "Recommended OS-level protections against network attacks.",
        "commands": {
            "linux": [
                "# /etc/sysctl.d/99-hardening.conf",
                "",
                "# SYN flood protection",
                "net.ipv4.tcp_syncookies = 1",
                "net.ipv4.tcp_max_syn_backlog = 4096",
                "net.ipv4.tcp_synack_retries = 2",
                "",
                "# Prevent IP spoofing",
                "net.ipv4.conf.all.rp_filter = 1",
                "net.ipv4.conf.default.rp_filter = 1",
                "",
                "# Disable ICMP redirects",
                "net.ipv4.conf.all.accept_redirects = 0",
                "net.ipv4.conf.all.secure_redirects = 0",
                "net.ipv4.conf.all.send_redirects = 0",
                "",
                "# Log suspicious packets",
                "net.ipv4.conf.all.log_martians = 1",
                "",
                "# Connection hardening",
                "net.ipv4.tcp_fin_timeout = 15",
                "net.ipv4.tcp_keepalive_time = 600",
                "",
                "# Apply",
                "sysctl -p /etc/sysctl.d/99-hardening.conf",
            ],
        },
        "diagram": (
            "  Attacker          Server\n"
            "    |--SYN-SYN-SYN-->|  SYN flood!\n"
            "    |--SYN-SYN-SYN-->|  Connection table\n"
            "    |--SYN-SYN-SYN-->|  fills up → DoS\n"
            "    |                 |\n"
            "  After fix (syncookies=1):\n"
            "    |--SYN-SYN-SYN-->|  SYN cookie\n"
            "    |                 |  validates before\n"
            "    |                 |  allocating memory\n"
            "    |                 |  → DoS blocked\n"
        ),
    }]


def _rate_limit_recommendations(result: dict) -> list[dict]:
    """Rate limiting recommendation for exposed services."""
    grade = result.get("grade", "A")
    if grade in ("A", "B"):
        return []

    return [{
        "category": "Rate Limiting",
        "priority": "medium",
        "title": "Configure Request Rate Limiting",
        "description": "Protect against brute-force and DDoS attacks.",
        "commands": {
            "nginx": [
                "# /etc/nginx/nginx.conf (http block)",
                "limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;",
                "limit_req_zone $binary_remote_addr zone=login:10m rate=3r/m;",
                "",
                "# In server/location block:",
                "limit_req zone=general burst=20 nodelay;",
                "",
                "# Login endpoints (stricter):",
                "location /login {",
                "    limit_req zone=login burst=5 nodelay;",
                "}",
                "systemctl reload nginx",
            ],
        },
    }]


def generate_hardening(result: dict) -> list[dict]:
    """Generate all hardening recommendations from scan result.

    Returns list of recommendation dicts sorted by priority.
    Each dict has: category, priority, title, description, commands, diagram (optional).
    """
    recs = []
    recs.extend(_ssl_recommendations(result))
    recs.extend(_header_recommendations(result))
    recs.extend(_redirect_recommendations(result))
    recs.extend(_disclosure_recommendations(result))
    recs.extend(_methods_recommendations(result))
    recs.extend(_dns_recommendations(result))
    recs.extend(_cookie_recommendations(result))
    recs.extend(_cors_recommendations(result))
    recs.extend(_kernel_recommendations(result))
    recs.extend(_rate_limit_recommendations(result))

    recs.sort(key=lambda r: _PRIORITY_ORDER.get(r["priority"], 3))
    return recs
