# CLAUDE.md — ContrastScan

## Project
Website security scanner. C binary (11 modules, 100pt) + Python FastAPI web app.
Live: contrastcyber.com | GitHub: UPinar/contrastscan

## Quick Reference
- **Run tests:** `cd app && python -m pytest tests/ -v` or `bash run_tests.sh`
- **Build C:** `cd scanner && make` (on server: `gcc -Wall -Wextra -O2 -o scanner/contrastscan scanner/src/contrastscan.c -lcurl -lssl -lcrypto -lresolv -lcjson`)
- **Deploy:** git clone + venv + pip + gcc (on server, ARM aarch64)
- **Server path:** `/opt/contrastscan/`
- **DB:** `/var/lib/contrastscan/scans.db`
- **Config overrides (server only):** SCAN_CONCURRENCY=8 in config.py
- **Lint:** `ruff check app/ && ruff format --check app/`
- **1071 tests (194 C + 877 Python)**

## Architecture
- `app/scanner.py` — orchestrates: validate → rate limit → C subprocess → enrich → save → recon
- `app/recon.py` — background passive recon (robots, sitemap, WHOIS, subdomains, CT logs)
- `app/findings.py` — vulnerability analysis from C scanner output
- `scanner/src/contrastscan.c` — single C binary, 11 modules, JSON output

## Key Rules
- C binary compiled ON SERVER (ARM), never upload local x86 binary
- `_SELF_DOMAINS` in scanner.py: contrastcyber.com scans via 127.0.0.1 (Cloudflare bypass)
- All cJSON allocations use safe_cjson_object/safe_cjson_array (NULL = clean exit, not segfault)
- Recon HTTP functions use domain names (not resolved_ip) for SSL compatibility; reverse_dns_lookup uses resolved_ip for PTR lookups
