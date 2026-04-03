"""API key authentication for ContrastScan Pro"""

import logging

from config import PRO_HOURLY_LIMIT
from db import check_pro_rate_limit, validate_api_key
from fastapi import HTTPException, Request

logger = logging.getLogger("contrastscan")


def require_api_key(request: Request, scan_count: int = 1) -> dict:
    """Extract and validate API key from X-API-Key header.
    scan_count: number of scans to reserve quota for (bulk scan passes len(domains)).
    Returns key info dict. Raises 401/403/429 on failure."""
    raw_key = request.headers.get("x-api-key", "")
    if not raw_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    if not raw_key.startswith("cs_") or len(raw_key) != 51:
        raise HTTPException(status_code=401, detail="Invalid API key format")

    key_data = validate_api_key(raw_key)
    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    allowed, usage = check_pro_rate_limit(key_data["id"], count=scan_count)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Pro rate limit reached ({usage}/{PRO_HOURLY_LIMIT}/hour). Requested {scan_count}, available {max(0, PRO_HOURLY_LIMIT - usage)}.",
        )

    return key_data
