# tests/unit/test_bopla.py
import pytest
import argparse
import requests
import json
from unittest.mock import MagicMock
from autoswagger2.analysis.bopla import BoplaTester

def test_resolve_schema_ref():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BoplaTester(args, session)

    spec = {
        'components': {
            'schemas': {
                'User': {'type': 'object', 'properties': {'name': {'type': 'string'}}}
            }
        }
    }
    schema = {'$ref': '#/components/schemas/User'}
    resolved = tester._resolve_schema_ref(schema, spec)
    assert resolved == {'type': 'object', 'properties': {'name': {'type': 'string'}}}

def test_find_bopla_targets():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BoplaTester(args, session)

    spec = {
        'paths': {
            '/users': {
                'post': {
                    'requestBody': {
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {'name': {'type': 'string'}}
                                }
                            }
                        }
                    }
                },
                'get': {}
            }
        }
    }

    targets = tester._find_bopla_targets(spec)
    assert len(targets) == 1
    assert targets[0]['path'] == '/users'
    assert targets[0]['method'] == 'post'
    assert targets[0]['schema'] == {'type': 'object', 'properties': {'name': {'type': 'string'}}}

def test_run_tests_vulnerable(monkeypatch):
    args = argparse.Namespace(verbose=False, product=True)
    session = requests.Session()
    tester = BoplaTester(args, session, bola_param="id", bola_id="42")

    spec = {
        'paths': {
            '/users/{id}': {
                'post': {
                    'requestBody': {
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {'name': {'type': 'string'}}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    called_urls = []

    def mock_request(method, url, **kwargs):
        called_urls.append(url)
        resp = MagicMock()
        resp.status_code = 200
        # Server reflects the mass-assigned body back as JSON
        resp.content = kwargs.get('data', '{}').encode('utf-8')
        return resp

    monkeypatch.setattr(session, "request", mock_request)

    results = tester.run_tests(spec, "http://localhost", "/api")
    assert all(u == "http://localhost/api/users/42" for u in called_urls)
    assert len(results) > 0
    assert results[0]['method'] == 'POST'
    assert results[0]['url_template'] == '/users/{id}'
    assert results[0]['vulnerable'] is True

    body_obj = json.loads(results[0]['request_body'])
    assert any(k in body_obj for k in ["isAdmin", "admin", "role", "permission", "is_admin"])


def test_run_tests_not_vulnerable_when_ignored(monkeypatch):
    args = argparse.Namespace(verbose=False, product=True)
    session = requests.Session()
    tester = BoplaTester(args, session)

    spec = {
        'swagger': '2.0',
        'paths': {
            '/users': {
                'put': {
                    'parameters': [{
                        'name': 'body',
                        'in': 'body',
                        'schema': {'type': 'object', 'properties': {'name': {'type': 'string'}}}
                    }]
                }
            }
        }
    }

    def mock_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        # Unknown extra fields ignored; only known 'name' returned
        resp.content = b'{"id": 1, "name": "alice"}'
        return resp

    monkeypatch.setattr(session, "request", mock_request)

    results = tester.run_tests(spec, "http://localhost", "/api")
    assert results == []


def test_bopla_edge_cases_error_envelope_and_ref_targets(monkeypatch):
    args = argparse.Namespace(verbose=False, product=True)
    session = requests.Session()
    tester = BoplaTester(args, session)

    # Error envelope on 200 should not count as mass assignment
    base_200 = MagicMock(status_code=200, content=b'{"id": 1}')
    err_200 = MagicMock(status_code=200, content=b'{"error": "ignored", "success": false}')
    assert tester._is_mass_assignment_confirmed(base_200, err_200, "isAdmin", True) is False

    # Baseline 400 -> attack 200 confirms acceptance
    base_400 = MagicMock(status_code=400, content=b'{"error": "missing"}')
    ok_200 = MagicMock(status_code=200, content=b'{"id": 1}')
    assert tester._is_mass_assignment_confirmed(base_400, ok_200, "isAdmin", True) is True

    # Identical plain text baseline vs attack -> False
    txt_a = MagicMock(status_code=200, content=b"success")
    txt_b = MagicMock(status_code=200, content=b"success")
    assert tester._is_mass_assignment_confirmed(txt_a, txt_b, "isAdmin", True) is False

    # $ref on requestBody in OpenAPI 3
    spec_rb_ref = {
        'components': {
            'requestBodies': {
                'UserBody': {
                    'content': {
                        'application/problem+json': {
                            'schema': {'type': 'object', 'properties': {'name': {'type': 'string'}}}
                        }
                    }
                }
            }
        },
        'paths': {
            '/users': {
                'patch': {'requestBody': {'$ref': '#/components/requestBodies/UserBody'}}
            }
        }
    }
    targets = tester._find_bopla_targets(spec_rb_ref)
    assert len(targets) == 1
    assert targets[0]['method'] == 'patch'
