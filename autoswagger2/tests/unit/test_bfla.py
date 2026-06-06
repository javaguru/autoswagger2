# tests/unit/test_bfla.py
import pytest
import argparse
import requests
from unittest.mock import MagicMock
from autoswagger2.analysis.bfla import BflaTester

def test_find_bfla_targets():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BflaTester(args, session)

    spec = {
        'paths': {
            '/users/{userId}': {
                'get': {
                    'parameters': [{'name': 'userId', 'in': 'path'}]
                }
            },
            '/admin/settings': {
                'post': {
                    'requestBody': {
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {'key': {'type': 'string'}}
                                }
                            }
                        }
                    }
                }
            },
            '/api/v1/management/users': {
                'get': {}
            }
        }
    }

    targets = tester._find_bfla_targets(spec)
    assert len(targets) == 2
    paths = [t['path'] for t in targets]
    assert '/admin/settings' in paths
    assert '/api/v1/management/users' in paths

    # Check schema extraction
    admin_target = next(t for t in targets if t['path'] == '/admin/settings')
    assert admin_target['schema'] is not None
    assert admin_target['schema']['type'] == 'object'

def test_analyze_response():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BflaTester(args, session)

    mock_resp_200 = MagicMock()
    mock_resp_200.status_code = 200
    assert tester._analyze_response(mock_resp_200) is True

    mock_resp_403 = MagicMock()
    mock_resp_403.status_code = 403
    assert tester._analyze_response(mock_resp_403) is False

def test_send_request(monkeypatch):
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BflaTester(args, session, bola_param="userId", bola_id="uuid-1234")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"success"

    def mock_request(method, url, **kwargs):
        assert url == "http://localhost/base/users/uuid-1234"
        return mock_response

    monkeypatch.setattr(session, "request", mock_request)

    parameters = [{'name': 'userId', 'in': 'path'}]
    url, response = tester._send_request("GET", "http://localhost", "/base", "/users/{userId}", parameters)
    assert url == "http://localhost/base/users/uuid-1234"
    assert response == mock_response

def test_run_tests_no_targets():
    args = argparse.Namespace(verbose=False, product=True)
    session = requests.Session()
    tester = BflaTester(args, session)
    spec = {'paths': {'/users': {'get': {}}}}

    results = tester.run_tests(spec, "http://localhost", "/api")
    assert results == []

def test_run_tests_vulnerable(monkeypatch):
    args = argparse.Namespace(verbose=False, product=True)
    session = requests.Session()
    tester = BflaTester(args, session)

    spec = {
        'paths': {
            '/admin/debug': {
                'get': {}
            }
        }
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"sensitive info"

    monkeypatch.setattr(session, "request", lambda method, url, **kwargs: mock_response)

    results = tester.run_tests(spec, "http://localhost", "/api")
    assert len(results) == 1
    assert results[0]['method'] == 'GET'
    assert results[0]['url_template'] == '/admin/debug'
    assert results[0]['status_code'] == 200
    assert results[0]['vulnerable'] is True
