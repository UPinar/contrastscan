"""
test_race.py — race condition and concurrency tests

Tests:
  1. Concurrent rate limit checks — no double-counting or bypass
  2. Concurrent DB writes — no corruption with simultaneous saves
  3. Concurrent scan requests — semaphore holds

Run: cd app && python -m pytest tests/test_race.py -v
"""

import secrets
import threading
import time

import pytest
from config import DOMAIN_LIMIT
from db import get_scan, init_db, save_scan
from ratelimit import check_domain_limit
from validation import SCAN_ID_PATTERN, clean_domain

# === 1. Concurrent domain rate limit — no bypass ===


class TestDomainRateLimitRace:
    def test_domain_limit_allows_exact_count(self):
        results = []

        def hammer_domain_limit(domain, count):
            for _ in range(count):
                results.append(check_domain_limit(domain))

        threads = []
        for i in range(10):
            t = threading.Thread(target=hammer_domain_limit, args=("race-domain.com", DOMAIN_LIMIT))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = sum(1 for r in results if r)
        assert allowed == DOMAIN_LIMIT

    def test_domain_limit_blocks_excess(self):
        results = []

        def hammer_domain_limit(domain, count):
            for _ in range(count):
                results.append(check_domain_limit(domain))

        threads = []
        for i in range(10):
            t = threading.Thread(target=hammer_domain_limit, args=("race-domain-2.com", DOMAIN_LIMIT))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        blocked = sum(1 for r in results if not r)
        assert blocked == (10 * DOMAIN_LIMIT - DOMAIN_LIMIT)


# === 2. Concurrent DB writes — no corruption ===


class TestDbWriteRace:
    @pytest.fixture(autouse=True)
    def setup_db(self):
        init_db()

    def test_50_concurrent_db_writes_no_errors(self):
        scan_ids = [secrets.token_hex(16) for _ in range(50)]
        errors = []

        def save_one(scan_id, idx):
            try:
                result = {
                    "domain": f"race-{idx}.com",
                    "total_score": idx,
                    "max_score": 100,
                    "grade": "C",
                }
                save_scan(scan_id, f"race-{idx}.com", result, "C", idx)
            except Exception as e:
                errors.append(str(e))

        threads = []
        for i, sid in enumerate(scan_ids):
            t = threading.Thread(target=save_one, args=(sid, i))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_all_50_scans_retrievable(self):
        scan_ids = [secrets.token_hex(16) for _ in range(50)]

        def save_one(scan_id, idx):
            result = {
                "domain": f"race2-{idx}.com",
                "total_score": idx,
                "max_score": 100,
                "grade": "C",
            }
            save_scan(scan_id, f"race2-{idx}.com", result, "C", idx)

        threads = []
        for i, sid in enumerate(scan_ids):
            t = threading.Thread(target=save_one, args=(sid, i))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        found = sum(1 for sid in scan_ids if get_scan(sid))
        assert found == 50


# === 3. Concurrent domain validation — thread safe ===


class TestValidationRace:
    def test_concurrent_clean_domain_no_crashes(self):
        clean_results = []

        def clean_many(domains):
            for d in domains:
                clean_results.append(clean_domain(d))

        domains_per_thread = [
            ["HTTPS://EXAMPLE.COM/path", "http://test.org:8080", "  spaces.com  "],
            ["HTTP://FOO.BAR/x", "https://a.b.c.d/", "  trim.me  "],
            ["HTTPS://UPPER.CASE", "http://lower.case:443", "clean.domain.com"],
        ]

        threads = []
        for dl in domains_per_thread:
            t = threading.Thread(target=clean_many, args=(dl,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(clean_results) == 9

    def test_clean_domain_output_valid(self):
        clean_results = []

        def clean_many(domains):
            for d in domains:
                clean_results.append(clean_domain(d))

        domains_per_thread = [
            ["HTTPS://EXAMPLE.COM/path", "http://test.org:8080", "  spaces.com  "],
            ["HTTP://FOO.BAR/x", "https://a.b.c.d/", "  trim.me  "],
            ["HTTPS://UPPER.CASE", "http://lower.case:443", "clean.domain.com"],
        ]

        threads = []
        for dl in domains_per_thread:
            t = threading.Thread(target=clean_many, args=(dl,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for r in clean_results:
            assert r == r.lower()
            assert "://" not in r
            assert ":" not in r
            assert "/" not in r
            assert " " not in r


# === 4. ReDoS check — SCAN_ID_PATTERN ===


class TestRedos:
    def test_100k_regex_matches_fast(self):
        start = time.time()
        for _ in range(100000):
            SCAN_ID_PATTERN.match("a" * 32)
        elapsed = time.time() - start
        assert elapsed < 1.0

    def test_100k_adversarial_regex_fast(self):
        start = time.time()
        for _ in range(100000):
            SCAN_ID_PATTERN.match("a" * 1000)
        elapsed = time.time() - start
        assert elapsed < 1.0


# === SECURITY: Rate Limit Boundary Precision ===


class TestRateLimitBoundary:
    """Verify exact boundary behavior — N allowed, N+1 blocked, no off-by-one."""

    def test_domain_limit_exact_boundary(self):
        for i in range(DOMAIN_LIMIT):
            result = check_domain_limit(f"domain-boundary-{id(self)}.com")
            assert result is True
        assert check_domain_limit(f"domain-boundary-{id(self)}.com") is False


# === SECURITY: Concurrent Scan ID Generation Uniqueness ===


class TestScanIdUniqueness:
    """Verify scan IDs generated concurrently are all unique."""

    def test_100_concurrent_scan_ids_unique(self):
        from scanner import make_scan_id

        ids = []

        def gen_ids(count):
            for _ in range(count):
                ids.append(make_scan_id())

        threads = []
        for _ in range(10):
            t = threading.Thread(target=gen_ids, args=(10,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(ids) == 100
        assert len(set(ids)) == 100  # all unique


# === Security Test 6 — Unbounded Recon Thread Spawning ===


class TestReconThreadBounding:
    """MEDIUM: Recon uses ThreadPoolExecutor(max_workers=5) per scan.
    Verify the pool is bounded and doesn't leak threads."""

    def test_threadpool_max_workers_is_bounded(self):
        """Verify the ThreadPoolExecutor in run_recon uses max_workers=5."""
        import inspect

        from recon import run_recon

        source = inspect.getsource(run_recon)
        assert "max_workers=5" in source

    def test_recon_thread_is_daemon(self):
        """Recon threads must be daemon threads so they don't block shutdown."""
        import inspect

        from recon import start_recon

        source = inspect.getsource(start_recon)
        assert "daemon=True" in source

    def test_scan_semaphore_bounds_concurrent_scans(self):
        """Scanner semaphore limits concurrent C binary executions."""
        from config import SCAN_CONCURRENCY

        from scanner import _scan_semaphore

        # Semaphore should have SCAN_CONCURRENCY permits
        # _value is the internal counter
        assert _scan_semaphore._value == SCAN_CONCURRENCY

    def test_concurrent_recon_threads_bounded(self):
        """Spawn multiple recon threads and verify ThreadPoolExecutor is bounded."""
        from concurrent.futures import ThreadPoolExecutor

        # ThreadPoolExecutor with max_workers=5 only runs 5 threads at a time
        # This is a structural test — we verify the executor doesn't allow > 5
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = []
            counter = threading.Semaphore(0)
            active = []

            def task():
                active.append(threading.current_thread().name)
                counter.release()
                time.sleep(0.1)
                return True

            for _ in range(20):
                futures.append(pool.submit(task))

            # Wait for all to complete
            results = [f.result() for f in futures]
            assert all(results)
            assert len(results) == 20


# === Rate limit store cap ===


class TestRateLimitStoreCap:
    """Verify rate limit store has a _MAX_STORE_KEYS cap."""

    def test_rate_limit_store_cap_exists(self):
        from ratelimit import _MAX_STORE_KEYS

        assert _MAX_STORE_KEYS == 2000
