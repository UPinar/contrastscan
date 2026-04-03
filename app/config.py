"""Configuration constants for ContrastScan"""

import hashlib
import os
import socket
from pathlib import Path

VERSION = "1.5.0"

BASE_DIR = Path(__file__).parent
_default_db = Path("/var/lib/contrastscan/scans.db")
DB_PATH = Path(
    os.environ.get("CONTRASTSCAN_DB", str(_default_db if _default_db.parent.exists() else BASE_DIR / "scans.db"))
)

# scanner binary — check scanner/ subdirectory first, then repo root (symlink)
_scanner_in_dir = BASE_DIR.parent / "scanner" / "contrastscan"
_scanner_in_root = BASE_DIR.parent / "contrastscan"
_default_scanner = _scanner_in_dir if _scanner_in_dir.exists() else _scanner_in_root
SCANNER_PATH = _default_scanner

# Rate limits
HOURLY_LIMIT = 100  # 100/hour per IP
DOMAIN_LIMIT = 10  # per-domain: 10/hour (all users)

SCAN_CONCURRENCY = 5
PRO_HOURLY_LIMIT = 1000  # Pro API key holders
BULK_MAX_DOMAINS = 50  # max domains per bulk scan request
SCAN_TIMEOUT = 30  # seconds
RECON_TIMEOUT = 5  # seconds per recon network operation
CRTSH_TIMEOUT = 30  # crt.sh can be slow for large domains (runs in parallel)

# Domain validation
MAX_DOMAIN_LENGTH = 253

# Badge SVG dimensions
BADGE_LABEL_WIDTH = 90
BADGE_GRADE_WIDTH = 40
BADGE_CACHE_MAX_AGE = 3600

# Report formatting
REPORT_LINE_WIDTH = 60

# Severity ordering (lower = more severe)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LEVELS = ("critical", "high", "medium", "low")

# Grade colors for UI
GRADE_COLORS = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}

# HMAC secret for IP hashing — deterministic fallback so hashes survive restarts
_raw_secret = os.environ.get("CONTRASTSCAN_HASH_SECRET", "")
HASH_SECRET = _raw_secret or hashlib.sha256(f"{socket.gethostname()}:{DB_PATH}".encode()).hexdigest()

# CSRF
ALLOWED_ORIGINS = {"https://contrastcyber.com", "https://www.contrastcyber.com"}

# Error pages
ERROR_MESSAGES = {
    400: ("Invalid Domain", "The domain you entered is not valid. Please enter a domain like example.com"),
    403: ("Forbidden", "This request was blocked."),
    404: ("Not Found", "The scan result you're looking for doesn't exist or has expired."),
    429: ("Rate Limit Reached", "You've reached the rate limit (100/hour). Come back later."),
    500: ("Server Error", "Something went wrong. Please try again."),
    502: ("Scan Failed", "The scanner couldn't reach the target. The domain may be offline or unreachable."),
    503: ("Server Busy", "Too many scans running. Please try again in a few seconds."),
    504: ("Scan Timed Out", "The scan took too long to complete. Please try again."),
}
