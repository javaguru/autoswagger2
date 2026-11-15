# autoswagger2/tests/unit/test_cache_and_concurrency.py
import argparse
import hashlib
import os
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from autoswagger2.analysis.bfla import BflaTester
from autoswagger2.analysis.bola import BolaTester
from autoswagger2.analysis.bopla import BoplaTester
from autoswagger2.analysis.pii import PiiAnalyzer
from autoswagger2.analysis.urc import UrcTester
from autoswagger2.core.requester import Requester
from autoswagger2.core.scanner import Scanner
from autoswagger2.discovery.finder import SpecFinder
from autoswagger2.utils.cache import SpecCache
from autoswagger2.utils.rate_limiter import RateLimiter, get_rate_limiter


def test_rate_limiter_noop_and_mock_args():
    assert RateLimiter(0).wait() == 0.0
    assert RateLimiter(-5).wait() == 0.0
    assert RateLimiter(True).wait() == 0.0
    assert get_rate_limiter(None).wait() == 0.0
    assert get_rate_limiter(argparse.Namespace()).wait() == 0.0
    assert get_rate_limiter(MagicMock()).wait() == 0.0


def test_rate_limiter_shared_instance_and_slot_spacing():
    args = argparse.Namespace(rate=10)
    limiters = []

    def grab():
        limiters.append(get_rate_limiter(args))

    threads = [threading.Thread(target=grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(set(id(lim) for lim in limiters)) == 1
    limiter = limiters[0]

    slept = []
    with patch("autoswagger2.utils.rate_limiter.time.monotonic", return_value=100.0), \
         patch("autoswagger2.utils.rate_limiter.time.sleep", side_effect=slept.append):
        d1 = limiter.wait()
        d2 = limiter.wait()
        d3 = limiter.wait()

    assert d1 == 0.0
    assert round(d2, 4) == 0.1
    assert round(d3, 4) == 0.2
    assert len(slept) == 2


def test_rate_limiter_called_across_all_http_clients():
    args = argparse.Namespace(
        rate=50,
        verbose=False,
        allow_external=False,
        product=False,
        stats=False,
        json=False,
        csv=False,
        sarif=False,
        html=False,
        out=None,
        severity=None,
        no_cache=True,
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b'{"ok": true}'
    mock_resp.text = '{"ok": true}'
    mock_resp.headers = {"Content-Type": "application/json"}
    mock_resp.json.return_value = {"ok": True}

    session = MagicMock()
    session.get.return_value = mock_resp
    session.request.return_value = mock_resp

    fake_limiter = MagicMock()
    with patch("autoswagger2.discovery.finder.get_rate_limiter", return_value=fake_limiter), \
         patch("autoswagger2.core.requester.get_rate_limiter", return_value=fake_limiter), \
         patch("autoswagger2.analysis.bola.get_rate_limiter", return_value=fake_limiter), \
         patch("autoswagger2.analysis.bfla.get_rate_limiter", return_value=fake_limiter), \
         patch("autoswagger2.analysis.bopla.get_rate_limiter", return_value=fake_limiter), \
         patch("autoswagger2.analysis.urc.get_rate_limiter", return_value=fake_limiter):
        finder = SpecFinder("http://api.local", args, session)
        finder._safe_get("http://api.local/openapi.json")
        assert finder.TOTAL_REQUESTS == 1

        req = Requester("http://api.local", args, session)
        req._send_request("GET", "http://api.local", "/users", [], {}, None, None)
        assert req.TOTAL_REQUESTS == 1

        bola = BolaTester(args, session)
        bola._send_request("GET", "http://api.local", "", "/users/{id}", "id", "2")
        assert bola.TOTAL_REQUESTS == 1

        bfla = BflaTester(args, session)
        bfla._send_request("GET", "http://api.local", "", "/admin/users", [])
        assert bfla.TOTAL_REQUESTS == 1

        bopla = BoplaTester(args, session)
        bopla._send_request("POST", "http://api.local", "", "/users", '{"isAdmin": true}')
        assert bopla.TOTAL_REQUESTS == 1

        urc = UrcTester(args, session)
        urc._send_request("GET", "http://api.local", "", "/items", "limit", 999)
        assert urc.TOTAL_REQUESTS == 1

    assert fake_limiter.wait.call_count == 6


def test_urc_excludes_rate_limiter_wait_from_response_time():
    args = argparse.Namespace(rate=10, verbose=False, allow_external=False)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"[]"
    session = MagicMock()
    session.request.return_value = mock_resp

    call_order = []

    class RecordingLimiter:
        def wait(self):
            call_order.append("wait")

    with patch("autoswagger2.analysis.urc.get_rate_limiter", return_value=RecordingLimiter()), \
         patch("autoswagger2.analysis.urc.time.time", side_effect=lambda: (call_order.append("time") or 100.0)):
        urc = UrcTester(args, session)
        urc._send_request("GET", "http://api.local", "", "/items", "limit", 10)

    assert call_order[0] == "wait"
    assert call_order[1:] == ["time", "time"]


def test_spec_cache_sha256_ttl_corrupt_and_disabled(tmp_path):
    cache_dir = tmp_path / "cache"
    cache = SpecCache(cache_dir=str(cache_dir), ttl=60, enabled=True)
    url = "https://api.example.com/openapi.json"
    expected_name = f"{hashlib.sha256(url.encode('utf-8')).hexdigest()}.json"

    spec = {"openapi": "3.0.0", "paths": {}}
    cache.cache_spec(url, spec)
    cache_file = cache_dir / expected_name
    assert cache_file.exists()
    assert cache.get_cached_spec(url) == spec

    # Expire via mtime in the past -> deleted and returns None
    old_time = time.time() - 120
    os.utime(cache_file, (old_time, old_time))
    assert cache.get_cached_spec(url) is None
    assert not cache_file.exists()

    # Corrupt JSON -> deleted and returns None
    cache_file.write_text("{corrupt", encoding="utf-8")
    assert cache.get_cached_spec(url) is None
    assert not cache_file.exists()

    # Non-dict JSON -> deleted and returns None
    cache_file.write_text("[1, 2, 3]", encoding="utf-8")
    assert cache.get_cached_spec(url) is None
    assert not cache_file.exists()

    # Disabled cache does not read or write
    disabled_dir = tmp_path / "disabled_cache"
    disabled = SpecCache(cache_dir=str(disabled_dir), ttl=60, enabled=False)
    disabled.cache_spec(url, spec)
    assert not disabled_dir.exists()
    assert disabled.get_cached_spec(url) is None


def test_spec_cache_concurrent_writes(tmp_path):
    cache = SpecCache(cache_dir=str(tmp_path / "c"), ttl=300, enabled=True)
    url = "https://api.example.com/spec.json"
    errors = []

    def worker(idx):
        try:
            cache.cache_spec(url, {"openapi": "3.0.0", "idx": idx})
            loaded = cache.get_cached_spec(url)
            assert loaded is None or isinstance(loaded, dict)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    final_spec = cache.get_cached_spec(url)
    assert isinstance(final_spec, dict)
    assert list(tmp_path.joinpath("c").glob("*.tmp")) == []


def test_finder_wires_no_cache_and_ttl(tmp_path):
    args = SimpleNamespace(no_cache=True, cache_ttl=45, verbose=False)
    finder = SpecFinder("http://api.local", args, MagicMock())
    assert finder.cache.enabled is False
    assert finder.cache.ttl == 45.0


def test_pii_analyzer_lazy_singleton_and_empty_fast_path():
    orig_shared = PiiAnalyzer._shared_analyzer
    PiiAnalyzer._shared_analyzer = None
    fake_engine = MagicMock()
    fake_engine.analyze.return_value = []

    try:
        with patch("autoswagger2.analysis.pii.AnalyzerEngine", return_value=fake_engine) as MockEngine:
            p1 = PiiAnalyzer()
            p2 = PiiAnalyzer()

            # Lazy: AnalyzerEngine not called during __init__ or empty input
            assert MockEngine.call_count == 0
            assert p1.analyze_content("") == (False, {})
            assert p1.analyze_content("   ") == (False, {})
            assert p1.analyze_content(None) == (False, {})
            assert MockEngine.call_count == 0

            # Shared initialization across threads builds AnalyzerEngine exactly once
            def run_analyze(inst):
                inst.analyze_content("Contact alice@example.com for details")

            threads = [threading.Thread(target=run_analyze, args=(p,)) for p in (p1, p2, p1, p2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert MockEngine.call_count == 1
            assert p1.analyzer is p2.analyzer

            # Instance override stays isolated
            custom = MagicMock()
            p1.analyzer = custom
            assert p1.analyzer is custom
            assert p2.analyzer is fake_engine
    finally:
        PiiAnalyzer._shared_analyzer = orig_shared


def test_scanner_concurrency_budget_and_thread_safe_stats():
    args = argparse.Namespace(
        threads=6,
        rate=0,
        verbose=False,
        product=False,
        stats=True,
        json=False,
        csv=False,
        sarif=False,
        html=False,
        out=None,
        severity=None,
        bola_id=None,
        test_bfla=False,
        test_bopla=False,
        bola=False,
        test_urc=False,
        allow_external=False,
        openapi_version=None,
    )
    urls = ["http://host1.local", "http://host2.local", "http://host3.local"]

    def make_finder(base_url, *a, **kw):
        finder = MagicMock()
        finder.TOTAL_REQUESTS = 2
        finder.find.return_value = ({"openapi": "3.0.0", "paths": {"/u": {"get": {}}}}, f"{base_url}/openapi.json")
        return finder

    observed_budgets = []

    def make_requester(api_base_url, *a, **kw):
        req = MagicMock()
        req.TOTAL_REQUESTS = 4

        def fake_test(spec, base_path):
            observed_budgets.append(req.max_workers)
            # Each of the 3 hosts reports 2 PII endpoints -> hosts_with_pii must equal 3 (not 1 or 6)
            return [
                {"pii_detected": True, "pii_detection_details": {"EMAIL_ADDRESS": {}}, "regex_patterns_found": {"r1": "pat1"}},
                {"pii_detected": True, "pii_detection_details": {"PHONE_NUMBER": {}}, "regex_patterns_found": {"r2": "pat2"}},
            ]

        req.test_endpoints.side_effect = fake_test
        return req

    with patch("autoswagger2.core.scanner.SpecFinder", side_effect=make_finder), \
         patch("autoswagger2.core.scanner.Requester", side_effect=make_requester), \
         patch("autoswagger2.core.scanner.Reporter") as MockReporter:
        scanner = Scanner(urls, args, MagicMock())
        scanner.run()

    assert observed_budgets == [2, 2, 2]
    assert scanner.stats["active_hosts"] == 3
    assert scanner.stats["hosts_with_valid_spec"] == 3
    assert scanner.stats["hosts_with_valid_endpoint"] == 3
    assert scanner.stats["hosts_with_pii"] == 3
    assert set(scanner.stats["pii_detection_methods"]) == {"EMAIL_ADDRESS", "PHONE_NUMBER"}
    assert set(scanner.stats["regexes_found"]) == {"pat1", "pat2"}
    assert scanner.TOTAL_REQUESTS == 18  # 3 * (2 finder + 4 requester)
    MockReporter.return_value.print_results.assert_called_once()


def test_requester_resolve_max_workers_bounds():
    req = Requester("http://api.local", argparse.Namespace(threads=16), MagicMock())
    assert req._resolve_max_workers(0) == 1
    assert req._resolve_max_workers(3) == 3
    assert req._resolve_max_workers(50) == 16

    req.max_workers = 4
    assert req._resolve_max_workers(50) == 4

    req_mock_args = Requester("http://api.local", MagicMock(), MagicMock())
    assert req_mock_args._resolve_max_workers(5) == 5
    assert req_mock_args._resolve_max_workers(50) == 20
