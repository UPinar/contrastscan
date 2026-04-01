"""
conftest.py — shared fixtures and helpers for ContrastScan tests
"""

import os
import sys
import tempfile
import uuid
from pathlib import Path

# Force tests to use a unique temporary DB per session — never touch production
_test_db = os.path.join(tempfile.gettempdir(), f"contrastscan_test_{uuid.uuid4().hex[:8]}.db")
os.environ["CONTRASTSCAN_DB"] = _test_db

# add parent dir to path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

# Initialize DB tables at import time (before any test runs)
from db import init_db

init_db()


# === Shared fixtures ===


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Reset all rate limit stores and clean up DB connections after each test."""
    from ratelimit import reset_all

    reset_all()
    # Also clear DB-based IP limits
    from db import get_db

    try:
        with get_db() as con:
            con.execute("DELETE FROM ip_limits")
    except Exception:
        pass
    yield
    reset_all()
    try:
        with get_db() as con:
            con.execute("DELETE FROM ip_limits")
    except Exception:
        pass
    # Close thread-local DB connection to prevent lock contention
    from db import close_thread_db

    close_thread_db()


@pytest.fixture
def init_test_db():
    """Initialize the test database."""
    from db import init_db

    init_db()


def pytest_sessionfinish(session, exitstatus):
    """Clean up test DB and WAL files after all tests complete."""
    # Checkpoint WAL and close connections before deleting
    try:
        from db import close_thread_db, get_db

        with get_db() as con:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        close_thread_db()
    except Exception:
        pass

    for suffix in ("", "-wal", "-shm"):
        f = _test_db + suffix
        if os.path.exists(f):
            os.remove(f)


# === Shared helpers ===


class FakeRequest:
    """Fake Request object for CSRF/IP tests."""

    def __init__(self, headers=None, client_host="127.0.0.1"):
        self.headers = headers or {}
        self.client = type("C", (), {"host": client_host})()
        self.url = type("U", (), {"path": "/scan"})()


def make_scan_result(
    headers_missing=None,
    ssl_error=None,
    tls_version="TLSv1.3",
    cert_valid=True,
    chain_valid=True,
    days_remaining=90,
    cipher="TLS_AES_256_GCM_SHA384",
    cipher_score=8,
    spf=True,
    dmarc=True,
    dkim=True,
    redirects_to_https=True,
    server_exposed=False,
    server_value="",
    powered_by_exposed=False,
    powered_by_value="",
    cookies_found=0,
    all_secure=True,
    all_httponly=True,
    all_samesite=True,
    dnssec_enabled=True,
    trace_enabled=False,
    delete_enabled=False,
    put_enabled=False,
    wildcard_origin=False,
    reflects_origin=False,
    credentials_with_wildcard=False,
    cors_credentials=False,
    mixed_active=0,
    mixed_passive=0,
    inline_scripts=0,
    inline_handlers=0,
    external_scripts=0,
    external_scripts_no_sri=0,
    forms_total=0,
    forms_http_action=0,
    meta_set_cookie=0,
    meta_refresh_http=0,
    csp_present=True,
    unsafe_inline=False,
    unsafe_eval=False,
    wildcard_source=False,
    data_uri=False,
    blob_uri=False,
):
    """Build a controlled scan result dict."""
    headers_missing = headers_missing or []

    header_details = []
    all_headers = [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]
    for h in all_headers:
        header_details.append({"header": h, "present": h not in headers_missing})

    found_count = sum(1 for d in header_details if d["present"])
    h_score = found_count * 5

    result = {
        "domain": "test.example.com",
        "headers": {
            "score": h_score,
            "max": 30,
            "details": header_details,
        },
        "redirect": {
            "score": 10 if redirects_to_https else 0,
            "max": 10,
            "details": {"redirects_to_https": redirects_to_https},
        },
        "disclosure": {
            "score": 5,
            "max": 5,
            "details": {
                "server_exposed": server_exposed,
                "powered_by_exposed": powered_by_exposed,
            },
        },
        "cookies": {
            "score": 5,
            "max": 5,
            "details": {"cookies_found": cookies_found},
        },
        "dnssec": {
            "score": 5 if dnssec_enabled else 0,
            "max": 5,
            "details": {"dnssec_enabled": dnssec_enabled},
        },
    }

    if server_exposed:
        result["disclosure"]["details"]["server_value"] = server_value
    if powered_by_exposed:
        result["disclosure"]["details"]["powered_by_value"] = powered_by_value

    if cookies_found > 0:
        result["cookies"]["details"]["all_secure"] = all_secure
        result["cookies"]["details"]["all_httponly"] = all_httponly
        result["cookies"]["details"]["all_samesite"] = all_samesite

    if ssl_error:
        result["ssl"] = {"score": 0, "max": 25, "error": ssl_error, "details": {}}
    else:
        result["ssl"] = {
            "score": 25,
            "max": 25,
            "details": {
                "tls_version": tls_version,
                "cipher": cipher,
                "cipher_score": cipher_score,
                "cert_valid": cert_valid,
                "chain_valid": chain_valid,
                "days_remaining": days_remaining,
            },
        }

    result["dns"] = {
        "score": (5 if spf else 0) + (5 if dmarc else 0) + (5 if dkim else 0),
        "max": 15,
        "details": {"spf": spf, "dmarc": dmarc, "dkim": dkim},
    }

    result["methods"] = {
        "score": 5,
        "max": 5,
        "details": {
            "trace_enabled": trace_enabled,
            "delete_enabled": delete_enabled,
            "put_enabled": put_enabled,
        },
    }

    result["cors"] = {
        "score": 5,
        "max": 5,
        "details": {
            "wildcard_origin": wildcard_origin,
            "reflects_origin": reflects_origin,
            "credentials_with_wildcard": credentials_with_wildcard,
            "cors_credentials": cors_credentials,
        },
    }

    result["html"] = {
        "score": 5,
        "max": 5,
        "details": {
            "mixed_active": mixed_active,
            "mixed_passive": mixed_passive,
            "inline_scripts": inline_scripts,
            "inline_handlers": inline_handlers,
            "external_scripts": external_scripts,
            "external_scripts_no_sri": external_scripts_no_sri,
            "forms_total": forms_total,
            "forms_http_action": forms_http_action,
            "meta_set_cookie": meta_set_cookie,
            "meta_refresh_http": meta_refresh_http,
        },
    }

    result["csp_analysis"] = {
        "score": 2,
        "max": 2,
        "details": {
            "csp_present": csp_present,
            "unsafe_inline": unsafe_inline,
            "unsafe_eval": unsafe_eval,
            "wildcard_source": wildcard_source,
            "data_uri": data_uri,
            "blob_uri": blob_uri,
        },
    }

    return result
