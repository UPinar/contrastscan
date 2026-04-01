# ContrastScan

[![Tests](https://github.com/UPinar/contrastscan/actions/workflows/tests.yml/badge.svg)](https://github.com/UPinar/contrastscan/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![C](https://img.shields.io/badge/Scanner-C-00599C.svg)](scanner/src/contrastscan.c)

**Free security scanner that grades any website A-F.** 11 checks, 100-point scoring, single JSON output. No signup, no API key.

**Live:** [contrastcyber.com](https://contrastcyber.com) | **API Platform:** [api.contrastcyber.com](https://api.contrastcyber.com)

![Security Grade](https://contrastcyber.com/badge/contrastcyber.com.svg)

## Why ContrastScan?

- **One grade, not a wall of text** — scan any domain, get a single A-F score in under 3 seconds
- **Written in C** — raw TLS handshakes, direct DNS queries, no runtime overhead
- **Self-hostable** — `git clone && bash setup.sh`, done
- **Free forever** — no signup, no API key, 100 requests/hour

## Quick Start

### CLI

```bash
make
./contrastscan example.com
```

```json
{
  "domain": "example.com",
  "total_score": 85,
  "max_score": 100,
  "grade": "B",
  "headers":      { "score": 21, "max": 25 },
  "ssl":          { "score": 20, "max": 20 },
  "dns":          { "score": 15, "max": 15 },
  "redirect":     { "score": 8,  "max": 8 },
  "disclosure":   { "score": 5,  "max": 5 },
  "cookies":      { "score": 5,  "max": 5 },
  "dnssec":       { "score": 0,  "max": 5 },
  "methods":      { "score": 5,  "max": 5 },
  "cors":         { "score": 5,  "max": 5 },
  "html":         { "score": 5,  "max": 5 },
  "csp_analysis": { "score": 1,  "max": 2 }
}
```

### Web App

```bash
git clone https://github.com/UPinar/contrastscan.git
cd contrastscan
bash setup.sh
source venv/bin/activate && cd app && uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` in your browser.

## API

Free, no key needed — 100 requests/hour per IP.

```bash
# JSON scan
curl "https://contrastcyber.com/api/scan?domain=example.com"

# Plain-text report
curl "https://contrastcyber.com/api/report?domain=example.com" -o report.txt

# Bulk scan
curl -X POST "https://contrastcyber.com/api/bulk" \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "google.com"]}'

# Grade badge (for your README)
# ![Security](https://contrastcyber.com/badge/yourdomain.com.svg)
```

| Endpoint | Description |
|----------|-------------|
| `GET /api/scan?domain=X` | JSON scan result with findings |
| `GET /api/report?domain=X` | Downloadable text report |
| `POST /api/bulk` | Bulk scan (JSON or CSV upload) |
| `GET /api/recon/{scan_id}` | Passive recon results |
| `GET /badge/{domain}.svg` | Dynamic SVG grade badge |

### Rate Limits

| Limit | Value |
|-------|-------|
| Per IP | 100/hour |
| Per domain | 10/hour |

## Scanner (11 modules, 100 points)

| Module | Max | What's Checked |
|--------|-----|----------------|
| Security Headers | 25 | CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| SSL/TLS | 20 | TLS version, cipher strength, certificate validity & chain verification |
| DNS Security | 15 | SPF, DKIM (MX-based provider detection + date probe), DMARC |
| HTTP Redirect | 8 | HTTP to HTTPS enforcement |
| Info Disclosure | 5 | Server / X-Powered-By header exposure |
| Cookie Security | 5 | Secure, HttpOnly, SameSite flags |
| DNSSEC | 5 | DNSKEY record presence |
| HTTP Methods | 5 | TRACE, PUT, DELETE detection |
| CORS | 5 | Wildcard origin, credential leakage |
| HTML Analysis | 5 | Mixed content, inline scripts, SRI |
| CSP Deep Analysis | 2 | unsafe-inline, unsafe-eval, wildcards |

### Grades

| Grade | Score |
|-------|-------|
| A | 90-100 |
| B | 75-89 |
| C | 60-74 |
| D | 40-59 |
| F | 0-39 |

## Web App Features

- Vulnerability findings with severity + remediation
- Enterprise detection (Google, Facebook, etc.)
- Bulk scan (CSV/TXT upload)
- Downloadable .txt report
- Dynamic SVG grade badge
- Stats dashboard with grade distribution
- Passive recon (WHOIS, tech stack, WAF, subdomains, CT logs)
- Subdomain takeover detection (30 services: GitHub Pages, Heroku, AWS S3, Azure, Shopify, Netlify, etc.)

## Security

- **SSRF protection** — DNS rebinding prevention via CURLOPT_RESOLVE
- **DB-based rate limiting** — IP hourly limits stored in SQLite
- **Input validation** — null byte, unicode, format string, injection protection
- **CSRF** — Origin + Referer header verification
- **Private IP blocking** — blocks all non-global IPs (RFC 1918, link-local, shared address space)

## Tests

```bash
bash run_tests.sh          # 1071 tests (no network)
bash run_tests.sh --all    # + live integration + smoke + load
```

| Suite | Tests | What |
|-------|-------|------|
| C Unit | 194 | Scoring, parsing, CDN detection |
| Backend | 337 | Validation, CSRF, rate limiting, findings |
| E2E | 133 | HTTP routes, templates, scan flow |
| Auth | 14 | Rate limiting, usage tracking |
| Race | 15 | Concurrent rate limits, DB writes |
| Fuzz | 148 | Injection, SSRF bypass, crash resistance |
| Integration | 64 | Module communication, config consistency |
| Recon | 163 | WHOIS, DNS, tech stack, subdomains, takeover detection |
| New Features | 6 | Bulk scan, OpenAPI, badges |

## Architecture

```
contrastscan/
├── scanner/                    # C scanner engine
│   ├── src/contrastscan.c      # Main scanner (2,287 LOC)
│   ├── Makefile                # C build system
│   └── tests/                  # C unit + integration tests
├── app/                        # Python FastAPI backend
│   ├── main.py                 # Routes
│   ├── config.py               # Constants
│   ├── db.py                   # SQLite (WAL mode, thread-local pool)
│   ├── scanner.py              # C binary execution + SSRF protection
│   ├── validation.py           # Domain/IP validation, CSRF
│   ├── ratelimit.py            # Domain rate limiting
│   ├── findings.py             # Vulnerability analysis, enterprise detection
│   ├── report.py               # Plain-text report generation
│   ├── recon.py                # Passive recon (WHOIS, tech stack, WAF, subdomains)
│   ├── templates/              # Jinja2 HTML (7 pages)
│   ├── static/                 # CSS, images
│   └── tests/                  # All tests (877 Python + shell)
├── scripts/                    # Deploy, setup, status scripts
├── run_tests.sh                # Run all tests
└── requirements.txt            # Python dependencies
```

## Stack

| C | Python |
|---|--------|
| libcurl | FastAPI |
| OpenSSL | Jinja2 |
| libresolv | uvicorn |
| cJSON | httpx |
| | dnspython |

## License

MIT
