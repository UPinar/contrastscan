# ContrastScan

[![Tests](https://github.com/UPinar/contrastscan/actions/workflows/tests.yml/badge.svg)](https://github.com/UPinar/contrastscan/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![C](https://img.shields.io/badge/Scanner-C-00599C.svg)](scanner/src/contrastscan.c)

**Free security scanner that grades any website A-F.** 11 checks, 100-point scoring, single JSON output. No signup, no API key.

**Live:** [contrastcyber.com](https://contrastcyber.com) | **API Platform:** [api.contrastcyber.com](https://api.contrastcyber.com)

![Security Grade](https://contrastcyber.com/badge/contrastcyber.com.svg)

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

## Grade Badge

Embed your domain's current grade in a README:

```markdown
![Security](https://contrastcyber.com/badge/yourdomain.com.svg)
```

## Programmatic Access

ContrastScan itself is a web app (scan via the form at [contrastcyber.com](https://contrastcyber.com)) — there is no public JSON API on this service. For programmatic scanning, use the sibling project:

- **[api.contrastcyber.com](https://api.contrastcyber.com)** — 40+ REST + MCP endpoints, free tier 100 req/h
- Or self-host and call the C binary directly: `./contrastscan example.com`

### Rate Limits (web UI)

| Limit | Value |
|-------|-------|
| Per IP | 100/hour |
| Per domain | 10/hour |

## Scanner (11 modules, 100 points)

| Module | Max | What's Checked |
|--------|-----|----------------|
| Security Headers | 25 | CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| SSL/TLS | 20 | TLS version, cipher strength, certificate validity & chain verification |
| DNS Security | 15 | SPF, DKIM (MX-based provider detection + date probe), DMARC (RFC 7489 organizational domain fallback for subdomains) |
| HTTP Redirect | 8 | HTTP to HTTPS enforcement |
| Info Disclosure | 5 | Server / X-Powered-By header exposure |
| Cookie Security | 5 | Secure, HttpOnly, SameSite flags |
| DNSSEC | 5 | DNSKEY record presence (zone apex walk-up for subdomains) |
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

- **Game of Life intro** — WASM-powered Conway's Game of Life animation on the landing page (C → Emscripten → 17KB .wasm)
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
bash run_tests.sh          # 1075 tests (no network)
bash run_tests.sh --all    # + live integration + smoke + load
```

| Suite | Tests | What |
|-------|-------|------|
| C Unit | 231 | Scoring, parsing, CDN detection, CSP helpers |
| Backend | 335 | Validation, CSRF, rate limiting, findings |
| E2E | 108 | HTTP routes, templates, scan flow |
| Race | 15 | Concurrent rate limits, DB writes |
| Fuzz | 148 | Injection, SSRF bypass, crash resistance |
| Integration | 64 | Module communication, config consistency |
| Recon | 169 | WHOIS, DNS, tech stack, subdomains, takeover detection |
| New Features | 5 | Bulk scan, OpenAPI, badges |

## Architecture

```
contrastscan/
├── scanner/                    # C scanner engine
│   ├── src/contrastscan.c      # Main scanner (1,927 LOC)
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
│   └── tests/                  # All tests (844 Python + shell)
├── wasm/                       # Game of Life (C → WASM via Emscripten)
│   ├── gol.c                   # Conway's Game of Life engine
│   ├── hashtable.c             # Spatial hash table
│   ├── gol.h                   # Headers + WASM exports
│   └── Makefile                # Emscripten build
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
