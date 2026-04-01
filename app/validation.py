"""Domain validation, IP checks, CSRF for ContrastScan"""

import ipaddress
import logging
import re
import socket

import dns.resolver
from config import ALLOWED_ORIGINS, MAX_DOMAIN_LENGTH
from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

SCAN_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")

# Pre-built frozenset for O(1) domain character validation (vs set() per call)
_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")


def clean_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = d.replace("\x00", "")  # strip null bytes
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix) :]
    d = d.split("/")[0]
    d = d.split(":")[0]
    d = d.rstrip(".")  # strip trailing DNS dot
    return d


def is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_reserved
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or not addr.is_global
        )
    except ValueError:
        return True


def _dns_fallback(domain: str) -> str | None:
    """Fallback DNS resolution via dnspython with public resolvers."""
    for ns in ("8.8.8.8", "1.1.1.1"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns]
            resolver.timeout = 2
            resolver.lifetime = 3
            answers = resolver.resolve(domain, "A")
            ip = str(answers[0])
            if is_private_ip(ip):
                return None
            logger.info("DNS fallback resolved %s via dnspython", domain)
            return ip
        except Exception:
            continue
    return None


def resolve_and_check(domain: str) -> str | None:
    """Resolve DNS, check if IP is private. Return first valid IP or None."""
    # Try system resolver first with strict timeout
    import threading

    result_box = [None]
    exc_box = [None]

    def _resolve():
        try:
            result_box[0] = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        except Exception as e:
            exc_box[0] = e

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout=3)
    if t.is_alive() or exc_box[0] is not None:
        return _dns_fallback(domain)
    results = result_box[0]
    if not results:
        return _dns_fallback(domain)
    for _family, _stype, _proto, _canonname, sockaddr in results:
        if is_private_ip(sockaddr[0]):
            return None
    return results[0][4][0]


def _is_valid_format(domain: str) -> bool:
    """Check domain format without DNS resolution."""
    if not domain or len(domain) > MAX_DOMAIN_LENGTH:
        return False
    if "." not in domain:
        return False
    if not all(c in _DOMAIN_CHARS for c in domain):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return False
    return True


def validate_domain(domain: str) -> str | None:
    """Validate domain and return resolved IP, or None if invalid."""
    if not _is_valid_format(domain):
        return None
    return resolve_and_check(domain)


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


_TRUSTED_PROXIES = {"127.0.0.1", "::1"}


def get_client_ip(request: Request) -> str:
    """Client IP — trust CF-Connecting-IP, X-Real-IP, X-Forwarded-For from known proxies."""
    direct_ip = request.client.host if request.client else "unknown"

    if direct_ip not in _TRUSTED_PROXIES:
        return direct_ip

    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        ip = cf_ip.strip()
        if is_valid_ip(ip):
            return ip
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        ip = real_ip.strip()
        if is_valid_ip(ip):
            return ip
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        if is_valid_ip(ip):
            return ip
    return direct_ip


def check_csrf(request: Request) -> None:
    """Verify Origin/Referer header to prevent cross-site form submissions.

    Rejects when: (1) Origin present but not allowed, (2) Referer present but
    not allowed, (3) BOTH Origin and Referer absent (defense against stripped headers).
    """
    origin = request.headers.get("origin")
    referer = request.headers.get("referer", "")
    if origin:
        if origin not in ALLOWED_ORIGINS:
            raise HTTPException(status_code=403, detail="Cross-origin request blocked")
        return
    if referer:
        if not any(referer.startswith(o) for o in ALLOWED_ORIGINS):
            raise HTTPException(status_code=403, detail="Cross-origin request blocked")
        return
    # Neither Origin nor Referer — block to prevent header-stripping attacks
    # API endpoints don't use check_csrf, so this only affects browser form POST
    raise HTTPException(status_code=403, detail="Missing origin header")
