# tests/unit/test_urc.py
import pytest
import argparse
import requests
from unittest.mock import MagicMock
from autoswagger2.analysis.urc import UrcTester

def test_find_urc_targets():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = UrcTester(args, session)

    spec = {
        'paths': {
            '/users': {
                'parameters': [{'name': 'limit', 'in': 'query'}],
                'get': {}
            },
            '/books': {
                'get': {
                    'parameters': [{'name': 'size', 'in': 'query'}]
                }
            },
            '/items': {
                'get': {
                    'parameters': [{'name': 'id', 'in': 'query'}]
                }
            }
        }
    }

    targets = tester._find_urc_targets(spec)
    assert len(targets) == 2
    paths = [t['path'] for t in targets]
    assert '/users' in paths
    assert '/books' in paths
    assert '/items' not in paths

def test_analyze_response():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = UrcTester(args, session)

    # Normal case
    assert tester._analyze_response(0.5, 200, 1000) is False

    # Vulnerable by response time
    assert tester._analyze_response(6.0, 200, 1000) is True

    # Vulnerable by timeout
    assert tester._analyze_response(10.0, "TIMEOUT", 0) is True

    # Vulnerable by payload size
    assert tester._analyze_response(1.0, 200, 600000) is True

def test_send_request_success(monkeypatch):
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = UrcTester(args, session)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"A" * 100

    monkeypatch.setattr(session, "request", lambda method, url, **kwargs: mock_response)

    url, duration, status, length = tester._send_request("GET", "http://localhost", "/api", "/users", "limit")
    assert "limit=999999" in url
    assert status == 200
    assert length == 100
    assert duration >= 0

def test_send_request_timeout(monkeypatch):
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = UrcTester(args, session)

    def mock_request_exception(*args, **kwargs):
        raise requests.exceptions.Timeout("Connection timed out")

    monkeypatch.setattr(session, "request", mock_request_exception)

    url, duration, status, length = tester._send_request("GET", "http://localhost", "/api", "/users", "limit")
    assert status == "TIMEOUT"
    assert length == 0

def test_run_tests_vulnerable(monkeypatch):
    args = argparse.Namespace(verbose=False, product=True)
    session = requests.Session()
    tester = UrcTester(args, session)

    spec = {
        'paths': {
            '/users': {
                'get': {
                    'parameters': [{'name': 'limit', 'in': 'query'}]
                }
            }
        }
    }

    # Simulate timeout which flags vulnerability
    def mock_request(*args, **kwargs):
        raise requests.exceptions.Timeout("timed out")

    monkeypatch.setattr(session, "request", mock_request)

    results = tester.run_tests(spec, "http://localhost", "/api")
    assert len(results) == 1
    assert results[0]['method'] == 'GET'
    assert results[0]['url_template'] == '/users'
    assert results[0]['parameter'] == 'limit'
    assert results[0]['vulnerable'] is True
