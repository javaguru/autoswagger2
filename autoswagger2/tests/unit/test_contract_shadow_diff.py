import json
import sys
from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest
import requests
from rich.console import Console

from autoswagger2.analysis.contract_auditor import ContractAuditor
from autoswagger2.core.requester import Requester
from autoswagger2.core.scanner import Scanner
from autoswagger2.discovery.hidden_finder import CANARY_SLUG
from autoswagger2.discovery.shadow_version_finder import ShadowVersionFinder
from autoswagger2.reporting.diff_engine import DiffEngine
from autoswagger2.reporting.reporter import Reporter


def _make_response(status_code=200, body="", content_type="application/json", headers=None):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.content = body.encode("utf-8") if isinstance(body, str) else body
    hdrs = {"Content-Type": content_type} if content_type is not None else {}
    if headers:
        hdrs.update(headers)
    resp.headers = hdrs
    return resp


def _make_args(**overrides):
    defaults = {
        "verbose": False,
        "risk": False,
        "all": False,
        "brute": False,
        "product": False,
        "json": False,
        "csv": False,
        "sarif": False,
        "html": False,
        "stats": False,
        "out": None,
        "rate": 0,
        "threads": 4,
        "allow_external": False,
        "openapi_version": None,
        "hidden": False,
        "hidden_wordlist": None,
        "shadow_versions": False,
        "audit_contract": False,
        "test_bfla": False,
        "test_bopla": False,
        "bola": False,
        "bola_id": None,
        "test_urc": False,
        "severity": None,
        "diff": None,
        "fail_on": None,
        "api_key": None,
        "api_key_src": None,
        "key_header": "Authorization",
    }
    defaults.update(overrides)
    return Namespace(**defaults)


def test_contract_auditor_unauthenticated_auth_drift_and_response_schema_drift():
    spec = {
        "openapi": "3.0.3",
        "security": [{"bearerAuth": []}],
        "components": {
            "schemas": {
                "BaseEntity": {
                    "type": "object",
                    "properties": {"id": {"type": "integer"}},
                },
                "UserPublicDTO": {
                    "allOf": [
                        {"$ref": "#/components/schemas/BaseEntity"},
                        {
                            "type": "object",
                            "properties": {
                                "username": {"type": "string"},
                                "profile": {
                                    "type": "object",
                                    "properties": {"bio": {"type": "string"}},
                                },
                            },
                        },
                    ]
                },
                "FreeMap": {
                    "type": "object",
                    "additionalProperties": True,
                },
            }
        },
        "paths": {
            "/v1/users": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/UserPublicDTO"},
                                    }
                                }
                            },
                        }
                    }
                }
            },
            "/v1/public-health": {
                "get": {
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/FreeMap"}
                                }
                            },
                        }
                    },
                }
            },
            "/v1/soft-denied": {
                "get": {
                    "responses": {"200": {"description": "soft error"}}
                }
            },
        },
    }

    def fake_request(method, url, headers=None, data=None, files=None, allow_redirects=False, timeout=10, **kwargs):
        if url.endswith("/v1/users"):
            body = json.dumps(
                [
                    {
                        "id": 1,
                        "username": "alice",
                        "passwordHash": "sha256$xyz",
                        "profile": {"bio": "dev", "internalRole": "ADMIN"},
                    }
                ]
            )
            return _make_response(200, body, "application/json")
        if url.endswith("/v1/public-health"):
            return _make_response(200, '{"status":"UP","arbitraryKey":123}', "application/json")
        if url.endswith("/v1/soft-denied"):
            return _make_response(200, '{"status":401,"error":"Unauthorized"}', "application/json")
        return _make_response(404, "", "application/json")

    session = MagicMock()
    session.headers = {"User-Agent": "AutoSwagger2/Test"}
    session.cookies = {}
    session.request.side_effect = fake_request

    requester = Requester("http://localhost:8080", _make_args(audit_contract=True), session)
    results = requester.test_endpoints(spec, "")

    by_path = {r["path_template"]: r for r in results}

    # 1. /v1/users triggers BOTH Auth Drift and Sensitive Undocumented Fields
    users_res = by_path["/v1/users"]
    assert users_res["contract_drift"]["auth_drift"] is True
    assert users_res["contract_drift"]["undocumented_fields"] == ["passwordHash", "profile.internalRole"]
    assert any("Contract Auth Drift" in ind for ind in users_res["vuln_indicators"])
    assert any("Sensitive Undocumented Fields" in ind for ind in users_res["vuln_indicators"])

    # 2. /v1/public-health has security=[] and additionalProperties=True -> zero drift
    health_res = by_path["/v1/public-health"]
    assert "contract_drift" not in health_res
    assert health_res["vuln_indicators"] == []

    # 3. /v1/soft-denied returned soft-401 JSON envelope -> no Auth Drift false positive
    denied_res = by_path["/v1/soft-denied"]
    assert "contract_drift" not in denied_res


def test_contract_auditor_authenticated_scan_verifies_unauthenticated_probe_and_oneof():
    spec = {
        "swagger": "2.0",
        "security": [{"apiKeyAuth": []}],
        "paths": {
            "/v1/account": {
                "get": {
                    "responses": {
                        "200": {
                            "schema": {
                                "oneOf": [
                                    {"type": "object", "properties": {"id": {"type": "integer"}, "tier": {"type": "string"}}},
                                    {"type": "object", "properties": {"id": {"type": "integer"}, "company": {"type": "string"}}},
                                ]
                            }
                        }
                    }
                }
            },
            "/v1/strict-protected": {
                "get": {
                    "responses": {
                        "200": {
                            "schema": {
                                "type": "object",
                                "properties": {"ok": {"type": "boolean"}},
                            }
                        }
                    }
                }
            },
        },
    }

    def fake_request(method, url, headers=None, cookies=None, **kwargs):
        hdrs = headers or {}
        # When Authorization is stripped (set to None in headers override), simulate unauth check
        is_unauth_probe = "Authorization" in hdrs and hdrs["Authorization"] is None
        if url.endswith("/v1/account"):
            # Public even without credentials + extra benign field 'region'
            return _make_response(200, '{"id":1,"tier":"pro","region":"EU"}', "application/json")
        if url.endswith("/v1/strict-protected"):
            if is_unauth_probe:
                return _make_response(401, '{"error":"Unauthorized"}', "application/json")
            return _make_response(200, '{"ok":true}', "application/json")
        return _make_response(404, "", "application/json")

    session = MagicMock()
    session.headers = {"User-Agent": "AutoSwagger2/Test", "Authorization": "Bearer valid_tok"}
    session.cookies = {}
    session.request.side_effect = fake_request

    requester = Requester("http://localhost:8080", _make_args(audit_contract=True), session)
    results = requester.test_endpoints(spec, "")
    by_path = {r["path_template"]: r for r in results}

    # /v1/account failed auth enforcement without token + had undocumented field 'region'
    acc_res = by_path["/v1/account"]
    assert acc_res["contract_drift"]["auth_drift"] is True
    assert acc_res["contract_drift"]["undocumented_fields"] == ["region"]
    assert any("Undocumented Response Fields): region" in ind for ind in acc_res["vuln_indicators"])

    # /v1/strict-protected returned 401 when Authorization was stripped -> NO Auth Drift!
    strict_res = by_path["/v1/strict-protected"]
    assert "contract_drift" not in strict_res
    assert requester.TOTAL_REQUESTS == 4  # 2 initial + 2 unauthenticated verification probes


def test_shadow_version_finder_discovers_zombie_versions_and_integrates_with_scanner():
    spec = {
        "paths": {
            "/mock/v2/users/{id}": {"get": {}},
            "/mock/v2/items": {"get": {}},
            "/mock/v1/items": {"get": {}},  # Already documented in v1 -> must be skipped!
        }
    }

    def fake_request(method, url, headers=None, data=None, allow_redirects=False, timeout=10):
        if CANARY_SLUG in url:
            return _make_response(404, '{"status":404}', "application/json")
        if url == "http://localhost:8082/nexus-backend/mock/v1/users/1":
            return _make_response(200, '{"id":1,"legacyEmail":"john.doe@example.com"}', "application/json")
        if url == "http://localhost:8082/nexus-backend/mock/beta/items":
            return _make_response(200, '[{"item":"preview"}]', "application/json")
        return _make_response(404, "", "application/json")

    session = MagicMock()
    session.request.side_effect = fake_request

    finder = ShadowVersionFinder(
        api_base_url="http://localhost:8082",
        base_path="/nexus-backend",
        args=_make_args(shadow_versions=True),
        session=session,
    )
    results = finder.discover_shadow_versions(spec)

    found_urls = {r["url"]: r for r in results}
    assert set(found_urls.keys()) == {
        "http://localhost:8082/nexus-backend/mock/v1/users/1",
        "http://localhost:8082/nexus-backend/mock/beta/items",
    }
    v1_res = found_urls["http://localhost:8082/nexus-backend/mock/v1/users/1"]
    assert v1_res["undocumented"] is True
    assert v1_res["pii_detected"] is True
    assert "Shadow/Zombie API Version (v1 sibling of v2)" in v1_res["vuln_indicators"]
    assert v1_res["shadow_version"]["from_version"] == "v2"
    assert v1_res["shadow_version"]["shadow_version"] == "v1"

    # Non-versioned spec returns [] cleanly
    empty_res = finder.discover_shadow_versions({"paths": {"/health": {"get": {}}}})
    assert empty_res == []


def test_diff_engine_utf16_baseline_html_json_console_and_fail_on_gate(tmp_path, capsys):
    # 1. Create a baseline JSON encoded in UTF-16LE (simulating Windows PowerShell '>' redirection)
    baseline_payload = {
        "results": [
            {
                "method": "GET",
                "url": "http://localhost:8080/v1/legacy-secret",
                "status_code": 200,
                "content_length": 80,
                "pii_detected": True,
                "pii_data": {"AWS API Key": ["AKIAQWERTYUIOPASDF12"]},
                "pii_detection_details": {"AWS API Key": {"detection_methods": ["regex"]}},
                "debug_info_detected": False,
                "vuln_indicators": [],
            },
            {
                "method": "GET",
                "url": "http://localhost:8080/v1/profile",
                "status_code": 200,
                "content_length": 40,
                "pii_detected": False,
                "debug_info_detected": False,
                "vuln_indicators": [],
            },
            {
                "method": "GET",
                "url": "http://localhost:8080/v1/fixed-debug",
                "status_code": 200,
                "content_length": 90,
                "pii_detected": False,
                "debug_info_detected": True,
                "vuln_indicators": [],
            },
            {
                "method": "GET",
                "url": "http://localhost:8080/v1/decommissioned",
                "status_code": 200,
                "content_length": 20,
                "pii_detected": False,
                "debug_info_detected": False,
                "vuln_indicators": [],
            },
        ],
        "bola_findings": [
            {"method": "GET", "url_template": "/v1/items/{id}", "vulnerable": False}
        ],
    }
    utf16_baseline = tmp_path / "baseline_ps.json"
    utf16_baseline.write_bytes(json.dumps(baseline_payload).encode("utf-16"))

    engine = DiffEngine()
    loaded_base = engine.load_baseline(str(utf16_baseline))
    assert len(loaded_base["results"]) == 4

    # 2. First check: identical scan to baseline -> --fail-on high with --diff does NOT fail despite legacy secret!
    diff_no_change = engine.compute_diff(
        loaded_base,
        baseline_payload["results"],
        bola_results=baseline_payload["bola_findings"],
    )
    assert diff_no_change["summary"]["has_regressions"] is False
    should_fail, _, _ = DiffEngine.evaluate_fail_on(
        "high",
        baseline_payload["results"],
        diff_report=diff_no_change,
    )
    assert should_fail is False

    # Standalone --fail-on high (without diff) DOES fail because of the critical secret
    should_fail_standalone, max_sc, count = DiffEngine.evaluate_fail_on(
        "high",
        baseline_payload["results"],
        diff_report=None,
    )
    assert should_fail_standalone is True
    assert max_sc == 4
    assert count == 1

    # 3. Now simulate a PR scan with a new @Hidden endpoint, a PII regression on /v1/profile,
    #    a resolved debug leak on /v1/fixed-debug, removed /v1/decommissioned, and a new BOLA finding!
    current_results = [
        baseline_payload["results"][0],  # unchanged legacy secret
        {
            "method": "GET",
            "url": "http://localhost:8080/v1/profile",
            "path_template": "/v1/profile",
            "status_code": 200,
            "content_length": 75,
            "pii_detected": True,
            "pii_data": {"EMAIL_ADDRESS": ["john.doe@example.com"]},
            "pii_detection_details": {"EMAIL_ADDRESS": {"detection_methods": ["presidio"]}},
            "debug_info_detected": False,
            "vuln_indicators": ["Contract Drift (Undocumented Response Fields): email"],
            "body": "",
        },
        {
            "method": "GET",
            "url": "http://localhost:8080/v1/fixed-debug",
            "path_template": "/v1/fixed-debug",
            "status_code": 200,
            "content_length": 20,
            "pii_detected": False,
            "debug_info_detected": False,
            "vuln_indicators": [],
            "body": "",
        },
        {
            "method": "GET",
            "url": "http://localhost:8080/v1/echo",
            "path_template": "/v1/echo",
            "status_code": 200,
            "content_length": 16,
            "pii_detected": False,
            "debug_info_detected": False,
            "undocumented": True,
            "interesting_response": True,
            "vuln_indicators": ["Undocumented Endpoint (@Hidden)"],
            "body": "",
        },
    ]
    current_bola = [{"method": "GET", "url_template": "/v1/items/{id}", "vulnerable": True, "baseline_id": "1", "attack_id": "2", "baseline_status": 200, "attack_status": 200}]

    diff_reg = engine.compute_diff(loaded_base, current_results, bola_results=current_bola)
    assert diff_reg["summary"]["new_endpoints_count"] == 1
    assert diff_reg["summary"]["regressions_count"] == 1
    assert diff_reg["summary"]["new_active_vulns_count"] == 1
    assert diff_reg["summary"]["resolved_issues_count"] == 1
    assert diff_reg["summary"]["removed_endpoints_count"] == 1
    assert diff_reg["summary"]["has_regressions"] is True

    should_fail_reg, max_reg_sc, reg_cnt = DiffEngine.evaluate_fail_on(
        "high", current_results, bola_results=current_bola, diff_report=diff_reg
    )
    assert should_fail_reg is True
    assert max_reg_sc == 4
    assert reg_cnt == 3  # new @Hidden (3), regressed /v1/profile (3), new BOLA (4)

    # 4. Verify Reporter console diff table, JSON --out file export, and HTML diff section
    console_args = _make_args()
    rep_console = Reporter(console_args)
    rep_console.console = Console(width=200)
    rep_console.diff_report = diff_reg
    rep_console.print_results(current_results, {}, bola_results=current_bola)
    out_text = capsys.readouterr().out
    assert "Baseline Diff Summary" in out_text
    assert "REGRESSION" in out_text
    assert "RESOLVED" in out_text

    json_out_file = tmp_path / "exported_scan.json"
    rep_json = Reporter(_make_args(json=True, out=str(json_out_file)))
    rep_json.diff_report = diff_reg
    rep_json.print_results(current_results, {})
    saved_json = json.loads(json_out_file.read_text(encoding="utf-8"))
    assert "diff" in saved_json
    assert saved_json["diff"]["summary"]["regressions_count"] == 1

    html_out_file = tmp_path / "diff_report.html"
    rep_html = Reporter(_make_args(html=True, out=str(html_out_file)))
    rep_html.diff_report = diff_reg
    rep_html.print_results(current_results, {}, bola_results=current_bola)
    html_text = html_out_file.read_text(encoding="utf-8")
    assert "Baseline Comparison (--diff)" in html_text
    assert "REGRESSION" in html_text


@patch("autoswagger2.core.scanner.SpecFinder")
@patch("autoswagger2.core.scanner.ShadowVersionFinder")
@patch("autoswagger2.core.scanner.Requester")
def test_scanner_orchestrates_shadow_diff_and_fail_on_exit_code(
    mock_requester_cls, mock_shadow_cls, mock_finder_cls, tmp_path
):
    baseline_file = tmp_path / "base.json"
    baseline_file.write_text(json.dumps({"results": []}), encoding="utf-8")

    mock_finder = MagicMock()
    mock_finder_cls.return_value = mock_finder
    mock_finder.TOTAL_REQUESTS = 1
    mock_finder.find.return_value = ({"paths": {"/v2/users": {"get": {}}}}, "http://example.com/v3/api-docs")

    mock_shadow = MagicMock()
    mock_shadow_cls.return_value = mock_shadow
    mock_shadow.TOTAL_REQUESTS = 4
    mock_shadow.discover_shadow_versions.return_value = [
        {
            "method": "GET",
            "url": "http://example.com/v1/users",
            "path_template": "/v1/users",
            "status_code": 200,
            "content_length": 50,
            "pii_detected": False,
            "undocumented": True,
            "interesting_response": True,
            "vuln_indicators": ["Shadow/Zombie API Version (v1 sibling of v2)"],
            "body": "",
        }
    ]

    mock_req = MagicMock()
    mock_req.TOTAL_REQUESTS = 2
    mock_req.test_endpoints.return_value = []
    mock_requester_cls.return_value = mock_req

    args = _make_args(
        product=True,
        shadow_versions=True,
        diff=str(baseline_file),
        fail_on="high",
    )
    scanner = Scanner(["http://example.com"], args, MagicMock())
    scanner.run()

    assert scanner.stats["shadow_endpoints_found"] == 1
    assert scanner.diff_report is not None
    assert scanner.diff_report["summary"]["new_endpoints_count"] == 1
    assert scanner.exit_code == 1
    assert scanner.TOTAL_REQUESTS == 7
