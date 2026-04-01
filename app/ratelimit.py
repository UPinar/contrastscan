"""Thread-safe rate limiting for ContrastScan"""

import threading
import time
from collections import deque

from config import DOMAIN_LIMIT

_lock = threading.Lock()
_MAX_STORE_KEYS = 2000


# domain store: domain → deque of timestamps (bounded)
_domain_store: dict[str, deque] = {}


def _expire_deque(dq: deque, cutoff: float) -> None:
    """Remove expired timestamps from front of deque where timestamp <= cutoff."""
    while dq and dq[0] <= cutoff:
        dq.popleft()


def check_domain_limit(domain: str) -> bool:
    """Check per-domain rate limit (10/hour). Returns True if allowed."""
    now = time.time()
    cutoff = now - 3600

    with _lock:
        # cleanup stale domains
        stale = [k for k, v in _domain_store.items() if not v or v[-1] < cutoff]
        for k in stale:
            del _domain_store[k]

        # Reject new domains if store is full (DoS protection)
        if domain not in _domain_store and len(_domain_store) >= _MAX_STORE_KEYS:
            by_age = sorted(_domain_store.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
            del _domain_store[by_age[0][0]]

        if domain not in _domain_store:
            _domain_store[domain] = deque(maxlen=DOMAIN_LIMIT + 1)
        dq = _domain_store[domain]
        _expire_deque(dq, cutoff)
        if len(dq) >= DOMAIN_LIMIT:
            return False
        dq.append(now)
        return True


def reset_all():
    """Reset all stores (for testing)"""
    with _lock:
        _domain_store.clear()
