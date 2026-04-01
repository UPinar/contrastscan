"""Thread-safe rate limiting for ContrastScan"""

import time
import threading
from collections import deque

from config import DOMAIN_LIMIT

_lock = threading.Lock()
_MAX_STORE_KEYS = 10000

# domain store: domain → deque of timestamps
_domain_store = {}


def _expire_deque(dq: deque, cutoff: float) -> None:
    """Remove expired timestamps from front of deque."""
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
        if len(_domain_store) >= _MAX_STORE_KEYS:
            by_age = sorted(_domain_store.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
            excess = len(_domain_store) - _MAX_STORE_KEYS + 1
            for k, _ in by_age[:excess]:
                if k not in stale:
                    del _domain_store[k]

        if domain not in _domain_store:
            _domain_store[domain] = deque()
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
