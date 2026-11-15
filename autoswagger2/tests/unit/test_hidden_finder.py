import json
from argparse import Namespace
from unittest.mock import MagicMock, patch

import requests

from autoswagger2.core.scanner import Scanner
from autoswagger2.discovery.hidden_finder import CANARY_SLUG, HiddenEndpointFinder
from autoswagger2.reporting.reporter import Reporter


def _make_response(status_code=200, body="", content_type="application/json", headers=None):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    if isinstance(body, bytes):
        resp.content = body
    else:
        resp.content = body.encode("utf-8")
    hdrs = {"Content-Type": content_type} if content_type is not None else {}
    if headers:
        hdrs.update(headers)
    resp.headers = hdrs
    return resp


def _default_args(**overrides):
    base = {
        "verbose": False,
        "risk": False,
        "all": False,
        "product": False,
        "json": False,
        "csv": False,
        "sarif": False,
        "html": False,
        "stats": False,
        "rate": 0,
        "threads": 4,
        "allow_external": False,
        "hidden": True,
        "hidden_wordlist": None,
        "severity": None,
    }
    base.update(overrides)
    return Namespace(**base)


def test_derive_prefixes_from_openapi_spec_and_versioned_base():
    spec = {
        "paths": {
            "/mock/v1/data": {"get": {}},
            "/mock/v1/proxy": {"post": {}},
            "/mock/v1/users/{id}": {"get": {}},
        }
    }
    finder = HiddenEndpointFinder(
        api_base_url="http://localhost:8082",
        base_path="/nexus-backend",
        args=_default_args(),
        session=MagicMock(),
    )
    prefixes = finder._derive_prefixes(spec)

    assert "/nexus-backend/mock/v1" in prefixes
    assert "/nexus-backend/mock" in prefixes
    assert "/nexus-backend" in prefixes
    assert "/nexus-backend/v1" in prefixes
    assert "/nexus-backend/api/v1" in prefixes
    # Collection noun right before {id} should not become a dictionary prefix
    assert "/nexus-backend/mock/v1/users" not in prefixes

    # Versioned base_path should include parent without producing /v1/v1
    finder_ver = HiddenEndpointFinder(
        api_base_url="http://localhost:8080",
        base_path="/api/v1",
        args=_default_args(),
        session=MagicMock(),
    )
    ver_prefixes = finder_ver._derive_prefixes({"paths": {"/items": {"get": {}}}})
    assert "/api/v1" in ver_prefixes
    assert "/api" in ver_prefixes
    assert "/api/v1/v1" not in ver_prefixes
    assert "/api/v1/api/v1" not in ver_prefixes


def test_discovers_spring_hidden_echo_and_skips_documented_routes():
    spec = {
        "paths": {
            "/mock/v1/data": {"get": {}},
            "/mock/v1/admin/config": {"get": {}},
        }
    }
    requested_urls = []

    def fake_request(method, url, headers=None, data=None, allow_redirects=False, timeout=10):
        requested_urls.append((method.upper(), url))
        if url.endswith("/nexus-backend/mock/v1/echo"):
            return _make_response(200, '{"echo":"pong"}', "application/json")
        if url.endswith("/nexus-backend/v1/echo"):
            return _make_response(200, '{"echo":"root-v1"}', "application/json")
        if url.endswith("/nexus-backend/actuator/env"):
            return _make_response(
                200,
                '{"datasource":"jdbc:postgresql://db.internal:5432/app"}',
                "application/json",
            )
        return _make_response(404, '{"status":404,"error":"Not Found"}', "application/json")

    session = MagicMock()
    session.request.side_effect = fake_request

    finder = HiddenEndpointFinder(
        api_base_url="http://localhost:8082",
        base_path="/nexus-backend",
        args=_default_args(),
        session=session,
        spec_url="http://localhost:8082/nexus-backend/v3/api-docs",
    )
    results = finder.discover(spec)

    found_urls = {r["url"] for r in results}
    assert "http://localhost:8082/nexus-backend/mock/v1/echo" in found_urls
    assert "http://localhost:8082/nexus-backend/v1/echo" in found_urls
    assert "http://localhost:8082/nexus-backend/actuator/env" in found_urls

    # Documented static route and spec_url must never be probed as hidden candidates
    probed_url_set = {u for _, u in requested_urls}
    assert "http://localhost:8082/nexus-backend/mock/v1/admin/config" not in probed_url_set
    assert "http://localhost:8082/nexus-backend/v3/api-docs" not in probed_url_set

    for res in results:
        assert res["undocumented"] is True
        assert res["interesting_response"] is True
        assert "Undocumented Endpoint (@Hidden)" in res["vuln_indicators"]

    env_res = next(r for r in results if r["url"].endswith("/actuator/env"))
    assert env_res["pii_detected"] is True
    assert finder.TOTAL_REQUESTS == len(requested_urls)


def test_soft_404_spa_and_json_catchall_filtering(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("echo\nhealth\nnonexistent\n", encoding="utf-8")

    spa_html = "<html><head><title>Frontend App</title></head><body><div id='root'>SPA</div></body></html>"

    def fake_request(method, url, headers=None, data=None, allow_redirects=False, timeout=10):
        # /nexus/v1 returns JSON catch-all echoing slug, except /nexus/v1/health which returns real UP status
        if "/nexus/v1/" in url:
            slug = url.rsplit("/nexus/v1/", 1)[-1]
            if slug == "health":
                return _make_response(200, '{"status":"UP"}', "application/json")
            return _make_response(
                200,
                json.dumps({"status": "missing", "message": f"Unknown path {slug}"}),
                "application/json",
            )
        # Other prefixes return SPA index.html 200 catch-all, except /nexus/echo which returns JSON
        if url.endswith("/nexus/echo"):
            return _make_response(200, '{"echo":"ok"}', "application/json")
        return _make_response(200, spa_html, "text/html")

    session = MagicMock()
    session.request.side_effect = fake_request

    with patch("autoswagger2.discovery.hidden_finder.HIDDEN_ENDPOINT_WORDS", ()):
        finder = HiddenEndpointFinder(
            api_base_url="http://localhost:8080",
            base_path="/nexus",
            args=_default_args(hidden_wordlist=str(wl)),
            session=session,
        )
        results = finder.discover({"paths": {}})

    found_urls = {r["url"] for r in results}
    assert found_urls == {
        "http://localhost:8080/nexus/echo",
        "http://localhost:8080/nexus/v1/health",
    }


def test_missing_query_param_400_auto_recovery_and_type_mismatch_skip(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("echo\n", encoding="utf-8")

    def fake_request(method, url, headers=None, data=None, allow_redirects=False, timeout=10):
        if CANARY_SLUG in url:
            return _make_response(404, '{"status":404}', "application/json")
        if url.startswith("http://localhost:8080/v1/echo"):
            if "customParam=test" in url:
                return _make_response(200, '{"echo":"test"}', "application/json")
            return _make_response(
                400,
                '{"status":400,"message":"Required request parameter \'customParam\' for method parameter type String is not present"}',
                "application/json",
            )
        if url.startswith("http://localhost:8080/v2/echo"):
            return _make_response(
                400,
                "Failed to convert value of type 'java.lang.String' to required type 'java.lang.Long'",
                "text/plain",
            )
        return _make_response(404, "", "application/json")

    session = MagicMock()
    session.request.side_effect = fake_request

    with patch("autoswagger2.discovery.hidden_finder.HIDDEN_ENDPOINT_WORDS", ()):
        finder = HiddenEndpointFinder(
            api_base_url="http://localhost:8080",
            base_path="",
            args=_default_args(hidden_wordlist=str(wl)),
            session=session,
        )
        results = finder.discover({"paths": {"/v1/items": {"get": {}}}})

    assert len(results) == 1
    assert results[0]["status_code"] == 200
    assert results[0]["url"].startswith("http://localhost:8080/v1/echo?")
    assert "customParam=test" in results[0]["url"]


def test_405_method_not_allowed_safe_vs_risk_and_table_rendering(tmp_path, capsys):
    from rich.console import Console

    wl = tmp_path / "words.txt"
    wl.write_text("# comment line\n/echo/\n../ignored\n", encoding="utf-8")

    def fake_request(method, url, headers=None, data=None, allow_redirects=False, timeout=10):
        if CANARY_SLUG in url:
            return _make_response(404, "", "application/json")
        if url == "http://localhost:8080/v1/echo":
            if method.upper() == "GET":
                return _make_response(405, "", "application/json", headers={"Allow": "POST, OPTIONS"})
            if method.upper() == "POST":
                ct = (headers or {}).get("Content-Type", "")
                if ct == "application/json":
                    return _make_response(415, "Unsupported Media Type", "text/plain")
                if ct == "text/plain" and data == "test":
                    return _make_response(200, "echo: test", "text/plain")
        return _make_response(404, "", "application/json")

    # 1. Safe mode (risk=False): no POST dispatched, 405 reported with Allowed Methods and shown in table
    safe_session = MagicMock()
    safe_session.request.side_effect = fake_request
    safe_args = _default_args(risk=False, all=False, hidden_wordlist=str(wl))

    with patch("autoswagger2.discovery.hidden_finder.HIDDEN_ENDPOINT_WORDS", ()):
        finder_safe = HiddenEndpointFinder("http://localhost:8080", "", safe_args, safe_session)
        safe_results = finder_safe.discover({"paths": {"/v1/users": {"get": {}}}})

    assert len(safe_results) == 1
    assert safe_results[0]["method"] == "GET"
    assert safe_results[0]["status_code"] == 405
    assert "Allowed Methods: POST" in safe_results[0]["vuln_indicators"]
    assert all(call.args[0].upper() == "GET" for call in safe_session.request.call_args_list)

    reporter = Reporter(safe_args)
    reporter.console = Console(width=200)
    reporter.print_results(safe_results, {})
    table_out = capsys.readouterr().out
    assert "405" in table_out
    assert "Undocumented Endpoint (@Hidden)" in table_out

    # 2. Risk mode (risk=True): POST tried with JSON -> 415 -> retried as text/plain -> 200 OK
    risk_session = MagicMock()
    risk_session.request.side_effect = fake_request
    risk_args = _default_args(risk=True, all=False, hidden_wordlist=str(wl))

    with patch("autoswagger2.discovery.hidden_finder.HIDDEN_ENDPOINT_WORDS", ()):
        finder_risk = HiddenEndpointFinder("http://localhost:8080", "", risk_args, risk_session)
        risk_results = finder_risk.discover({"paths": {"/v1/users": {"get": {}}}})

    assert len(risk_results) == 1
    assert risk_results[0]["method"] == "POST"
    assert risk_results[0]["status_code"] == 200
    assert risk_results[0]["body"] == "test"
    assert risk_results[0]["response_body"] == "echo: test"


def test_hidden_finder_edge_cases_soft404_500_cross_origin_and_missing_wordlist():
    # 1. Cross-origin blocked when auth_origin differs and allow_external=False
    blocked_session = MagicMock()
    finder_blocked = HiddenEndpointFinder(
        api_base_url="http://external.example.org",
        base_path="",
        args=_default_args(allow_external=False, verbose=True, hidden_wordlist="nonexistent_file_xyz.txt"),
        session=blocked_session,
        auth_origin="http://localhost:8080",
    )
    assert finder_blocked.discover({"paths": {}}) == []
    blocked_session.request.assert_not_called()

    # 2. Soft-404 JSON 200 envelope, parameterized {id} 405 skip, and 500 stack trace detection
    def fake_request(method, url, headers=None, data=None, allow_redirects=False, timeout=10):
        if CANARY_SLUG in url:
            return _make_response(404, '{"status":404}', "application/json")
        if url == "http://localhost:8080/v1/echo":
            # Soft-404 disguised as HTTP 200
            return _make_response(200, '{"status":404,"error":"Not Found"}', "application/json")
        if url == "http://localhost:8080/v1/debug":
            return _make_response(
                500,
                "Traceback (most recent call last):\n  File \"app.py\", line 42, in debug_view\nZeroDivisionError: division by zero\n" + (" " * 80),
                "text/plain",
            )
        if url == "http://localhost:8080/v1/ping":
            # Matches documented /v1/{slug} and returns 405 -> must be skipped
            return _make_response(405, "", "application/json")
        return _make_response(404, "", "application/json")

    session = MagicMock()
    session.request.side_effect = fake_request

    with patch("autoswagger2.discovery.hidden_finder.HIDDEN_ENDPOINT_WORDS", ("echo", "debug", "ping")), \
         patch("autoswagger2.discovery.hidden_finder.COMMON_API_PREFIXES", ("/v1",)):
        finder = HiddenEndpointFinder(
            api_base_url="http://localhost:8080",
            base_path="",
            args=_default_args(),
            session=session,
        )
        results = finder.discover({"paths": {"/v1/{slug}": {"post": {}}}})

    # /v1/echo (soft-404) and /v1/ping (405 matching /v1/{slug}) are skipped; /v1/debug (500 matching /v1/{slug}) also skipped on param template!
    assert results == []

    # Without /v1/{slug} param template, /v1/debug 500 stack trace IS reported
    with patch("autoswagger2.discovery.hidden_finder.HIDDEN_ENDPOINT_WORDS", ("echo", "debug")), \
         patch("autoswagger2.discovery.hidden_finder.COMMON_API_PREFIXES", ("/v1",)):
        finder2 = HiddenEndpointFinder(
            api_base_url="http://localhost:8080",
            base_path="",
            args=_default_args(),
            session=session,
        )
        results2 = finder2.discover({"paths": {"/v1/items": {"get": {}}}})

    assert len(results2) == 1
    assert results2[0]["url"] == "http://localhost:8080/v1/debug"
    assert results2[0]["status_code"] == 500
    assert results2[0]["debug_info_detected"] is True


@patch("autoswagger2.core.scanner.SpecFinder")
@patch("autoswagger2.core.scanner.HiddenEndpointFinder")
@patch("autoswagger2.core.scanner.Requester")
def test_scanner_runs_hidden_discovery_before_schema_endpoints_and_on_no_spec(
    mock_requester_cls, mock_hidden_cls, mock_spec_finder_cls
):
    call_order = []

    mock_finder = MagicMock()
    mock_spec_finder_cls.return_value = mock_finder
    mock_finder.TOTAL_REQUESTS = 2
    mock_finder.find.return_value = ({"paths": {"/v1/users": {"get": {}}}}, "http://example.com/v3/api-docs")

    mock_hidden = MagicMock()
    mock_hidden_cls.return_value = mock_hidden
    mock_hidden.TOTAL_REQUESTS = 10

    def fake_discover(spec):
        call_order.append("hidden_discover")
        return [
            {
                "method": "GET",
                "url": "http://example.com/v1/echo",
                "path_template": "/v1/echo",
                "status_code": 200,
                "content_length": 15,
                "pii_detected": False,
                "undocumented": True,
                "vuln_indicators": ["Undocumented Endpoint (@Hidden)"],
                "interesting_response": True,
            }
        ]

    mock_hidden.discover.side_effect = fake_discover

    mock_requester = MagicMock()
    mock_requester_cls.return_value = mock_requester
    mock_requester.TOTAL_REQUESTS = 3

    def fake_test_endpoints(spec, base_path):
        call_order.append("test_endpoints")
        return [
            {
                "method": "GET",
                "url": "http://example.com/v1/users",
                "path_template": "/v1/users",
                "status_code": 200,
                "content_length": 40,
                "pii_detected": False,
            }
        ]

    mock_requester.test_endpoints.side_effect = fake_test_endpoints

    args = _default_args(hidden=True, product=True)
    scanner = Scanner(["http://example.com"], args, MagicMock())
    scanner.process_url("http://example.com")

    assert call_order == ["hidden_discover", "test_endpoints"]
    assert len(scanner.all_results) == 2
    assert scanner.all_results[0]["url"] == "http://example.com/v1/echo"
    assert scanner.stats["undocumented_endpoints_found"] == 1
    assert scanner.TOTAL_REQUESTS == 15

    # Also verify fallback when no OpenAPI spec is found but --hidden is True
    call_order.clear()
    mock_finder.find.return_value = (None, None)
    scanner_no_spec = Scanner(["http://example.com/app"], args, MagicMock())
    scanner_no_spec.process_url("http://example.com/app")
    assert call_order == ["hidden_discover"]
    assert len(scanner_no_spec.all_results) == 1
    assert scanner_no_spec.stats["undocumented_endpoints_found"] == 1
