import pytest
from unittest.mock import MagicMock, patch
from argparse import Namespace
from autoswagger2.core.scanner import Scanner

def test_scanner_init():
    args = Namespace(product=True, verbose=False, test_bfla=False, test_bopla=False, bola=False, test_urc=False, bola_id=None, stats=True)
    urls = ["http://localhost:8080"]
    session = MagicMock()
    scanner = Scanner(urls, args, session)
    assert scanner.urls == urls
    assert scanner.args == args
    assert scanner.session == session
    assert scanner.stats["unique_hosts_provided"] == 1

def test_get_base_path():
    args = Namespace(product=True, verbose=False)
    scanner = Scanner([], args, MagicMock())

    # Case 1: servers exists in spec
    spec1 = {"servers": [{"url": "http://example.com/api/v1"}]}
    assert scanner._get_base_path(spec1, "http://example.com/spec") == "/api/v1"

    # Case 2: basePath exists in spec
    spec2 = {"basePath": "/api/v2/"}
    assert scanner._get_base_path(spec2, "http://example.com/spec") == "/api/v2"

    # Case 3: fallback on spec url containing common path dirs
    spec3 = {}
    assert scanner._get_base_path(spec3, "http://example.com/api/v3/api-docs") == "/api"
    assert scanner._get_base_path(spec3, "http://example.com/v1/swagger.json") == ""
    assert scanner._get_base_path(spec3, "http://example.com/docs/swagger.json") == ""

def test_find_bola_targets():
    scanner = Scanner([], MagicMock(), MagicMock())
    spec = {
        "paths": {
            "/users/{userId}": {
                "get": {},
                "put": {}
            },
            "/users/profile": {
                "get": {}
            }
        }
    }
    targets = scanner._find_bola_targets(spec, "userId")
    assert len(targets) == 2
    assert {"path": "/users/{userId}", "method": "get"} in targets
    assert {"path": "/users/{userId}", "method": "put"} in targets

def test_calculate_stats():
    scanner = Scanner([], MagicMock(), MagicMock())
    scanner.TOTAL_REQUESTS = 10
    scanner.stats["active_hosts"] = 2
    scanner.stats["hosts_with_valid_endpoint"] = 1
    scanner.stats["pii_detection_methods"] = {"regex", "presidio"}
    scanner.stats["regexes_found"] = {"pattern1"}

    scanner._calculate_stats(100.0, 102.0)
    assert scanner.stats["percentage_hosts_with_endpoint"] == 50.0
    assert scanner.stats["total_requests_sent"] == 10
    assert scanner.stats["average_requests_per_second"] == 5.0
    assert isinstance(scanner.stats["pii_detection_methods"], list)
    assert "regex" in scanner.stats["pii_detection_methods"]
    assert isinstance(scanner.stats["regexes_found"], list)
    assert "pattern1" in scanner.stats["regexes_found"]

@patch("autoswagger2.core.scanner.SpecFinder")
@patch("autoswagger2.core.scanner.Requester")
def test_process_url(mock_requester_cls, mock_spec_finder_cls):
    # Setup mocks
    mock_finder = MagicMock()
    mock_spec_finder_cls.return_value = mock_finder
    mock_finder.find.return_value = ({"paths": {}}, "http://example.com/v1/swagger.json")

    mock_requester = MagicMock()
    mock_requester_cls.return_value = mock_requester
    mock_requester.TOTAL_REQUESTS = 5
    mock_requester.test_endpoints.return_value = [
        {"pii_detected": True, "pii_detection_details": {"email": {}}, "regex_patterns_found": {"p1": "pattern1"}},
        {"pii_detected": False}
    ]

    args = Namespace(product=True, verbose=False)
    scanner = Scanner(["http://example.com"], args, MagicMock())
    scanner.process_url("http://example.com")

    assert scanner.stats["active_hosts"] == 1
    assert scanner.stats["hosts_with_valid_spec"] == 1
    assert scanner.stats["hosts_with_valid_endpoint"] == 1
    assert scanner.stats["hosts_with_pii"] == 1
    assert "email" in scanner.stats["pii_detection_methods"]
    assert "pattern1" in scanner.stats["regexes_found"]
    assert scanner.TOTAL_REQUESTS == 5

@patch("autoswagger2.core.scanner.SpecFinder")
def test_process_url_no_spec(mock_spec_finder_cls):
    mock_finder = MagicMock()
    mock_spec_finder_cls.return_value = mock_finder
    mock_finder.find.return_value = (None, None)

    args = Namespace(product=True, verbose=False)
    scanner = Scanner(["http://example.com"], args, MagicMock())
    scanner.process_url("http://example.com")

    assert scanner.stats["active_hosts"] == 1
    assert scanner.stats["hosts_with_valid_spec"] == 0
    assert scanner.stats["hosts_with_valid_endpoint"] == 0

@patch("autoswagger2.core.scanner.BflaTester")
@patch("autoswagger2.core.scanner.BoplaTester")
@patch("autoswagger2.core.scanner.BolaTester")
@patch("autoswagger2.core.scanner.UrcTester")
@patch("autoswagger2.core.scanner.Reporter")
def test_run_with_scans(mock_reporter_cls, mock_urc_cls, mock_bola_cls, mock_bopla_cls, mock_bfla_cls):
    mock_reporter = MagicMock()
    mock_reporter_cls.return_value = mock_reporter

    # Setup BFLA mock
    mock_bfla = MagicMock()
    mock_bfla_cls.return_value = mock_bfla
    mock_bfla.run_tests.return_value = [{"vulnerable": True}]

    # Setup BOPLA mock
    mock_bopla = MagicMock()
    mock_bopla_cls.return_value = mock_bopla
    mock_bopla.run_tests.return_value = [{"vulnerable": False}]

    # Setup BOLA mock
    mock_bola = MagicMock()
    mock_bola_cls.return_value = mock_bola
    mock_bola.run_tests.return_value = [{"vulnerable": True}]

    # Setup URC mock
    mock_urc = MagicMock()
    mock_urc_cls.return_value = mock_urc
    mock_urc.run_tests.return_value = [{"vulnerable": False}]

    args = Namespace(
        product=True,
        verbose=False,
        test_bfla=True,
        test_bopla=True,
        bola=True,
        bola_id="userId=123",
        test_urc=True,
        stats=True
    )
    scanner = Scanner(["http://example.com"], args, MagicMock())
    scanner.processed_specs["http://example.com/swagger.json"] = {
        "spec": {
            "paths": {
                "/users/{userId}": {
                    "get": {}
                }
            }
        },
        "base_path": "/api"
    }

    # Avoid processing urls in run
    with patch.object(scanner, "process_url") as mock_process:
        scanner.run()
        mock_process.assert_called_once_with("http://example.com")

    # Assert testers were run
    mock_bfla.run_tests.assert_called_once()
    mock_bopla.run_tests.assert_called_once()
    mock_bola.run_tests.assert_called_once()
    mock_urc.run_tests.assert_called_once()

    assert len(scanner.bfla_results) == 1
    assert len(scanner.bopla_results) == 1
    assert len(scanner.bola_results) == 1
    assert len(scanner.urc_results) == 1
    mock_reporter.print_results.assert_called_once()

def test_run_invalid_bola_id(caplog):
    args = Namespace(
        product=True,
        verbose=False,
        test_bfla=False,
        test_bopla=False,
        bola=True,
        bola_id="invalid_format_no_equals",
        test_urc=False,
        stats=True
    )
    scanner = Scanner([], args, MagicMock())
    scanner.run()
