"""Scanner execution and orchestration for ContrastScan"""

import json
import logging
import secrets
import subprocess
import threading

from fastapi import HTTPException

from config import SCANNER_PATH, SCAN_CONCURRENCY, SCAN_TIMEOUT, HOURLY_LIMIT
from db import save_scan, check_and_increment_ip, hash_client_ip
from validation import clean_domain, validate_domain, _is_valid_format
from ratelimit import check_domain_limit
from findings import enrich_with_findings

logger = logging.getLogger("contrastscan")

_scan_semaphore = threading.Semaphore(SCAN_CONCURRENCY)


def run_scan(domain: str, resolved_ip: str | None = None) -> dict:
    """Run contrastscan binary, parse JSON. Pass resolved_ip to pin DNS (SSRF protection)."""
    acquired = _scan_semaphore.acquire(timeout=10)
    if not acquired:
        raise HTTPException(status_code=503, detail="Server busy. Try again in a few seconds.")
    try:
        cmd = [str(SCANNER_PATH), domain]
        if resolved_ip:
            cmd.append(resolved_ip)
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=SCAN_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        logger.warning("Scan timeout: %s", domain)
        raise HTTPException(status_code=504, detail="Scan timed out")
    except FileNotFoundError:
        logger.error("Scanner binary not found: %s", SCANNER_PATH)
        raise HTTPException(status_code=500, detail="Scanner not available")
    finally:
        _scan_semaphore.release()

    if result.returncode != 0:
        logger.warning("Scan failed: %s (exit %d)", domain, result.returncode)
        raise HTTPException(status_code=502, detail="Scan failed")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error("Invalid scanner JSON for %s", domain)
        raise HTTPException(status_code=502, detail="Scan failed")


def make_scan_id() -> str:
    return secrets.token_hex(16)


# Domains hosted on this server — bypass Cloudflare by scanning via localhost
_SELF_DOMAINS = {"contrastcyber.com", "www.contrastcyber.com"}


def perform_scan(domain: str, client_ip: str, dnt: bool = False) -> tuple[str, dict]:
    """Validate, rate limit, scan, save. Returns (scan_id, result).
    If dnt=True (DNT or Sec-GPC header set), client_hash is not stored."""
    domain = clean_domain(domain)
    resolved_ip = validate_domain(domain)

    # Self-scan: bypass Cloudflare loop by using localhost
    if domain in _SELF_DOMAINS and resolved_ip:
        resolved_ip = "127.0.0.1"
    if not resolved_ip:
        if _is_valid_format(domain):
            raise HTTPException(status_code=422, detail="Could not resolve this domain. Some regional domains (.com.tr, .com.br, etc.) may not be reachable from our servers.")
        raise HTTPException(status_code=400, detail="Invalid domain")

    # domain rate limit (all users)
    if not check_domain_limit(domain):
        raise HTTPException(status_code=429, detail="This domain has been scanned too many times. Try again later.")

    # IP hourly limit
    allowed, usage = check_and_increment_ip(client_ip, HOURLY_LIMIT)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit reached ({usage}/{HOURLY_LIMIT}/hour). Come back later.")

    log_ip = "dnt" if dnt else hash_client_ip(client_ip)
    logger.info("Scanning %s (ip=%s, resolved=%s)", domain, log_ip, resolved_ip)
    result = run_scan(domain, resolved_ip)
    result["resolved_ip"] = resolved_ip
    result = enrich_with_findings(result)
    scan_id = make_scan_id()

    save_scan(
        scan_id, domain, result,
        result.get("grade", "F"),
        result.get("total_score", 0),
        client_hash='' if dnt else hash_client_ip(client_ip),
    )

    # start background recon
    from recon import start_recon
    start_recon(scan_id, domain, result)

    return scan_id, result
