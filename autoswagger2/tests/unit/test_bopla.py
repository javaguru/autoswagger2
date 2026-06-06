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
                }
            }
        }
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"success"

    # We mock the session.request and also mock the Requester._build_request_body in our test context
    monkeypatch.setattr(session, "request", lambda method, url, **kwargs: mock_response)

    results = tester.run_tests(spec, "http://localhost", "/api")
    # Should have run tests by injecting key-values and got 200 responses
    assert len(results) > 0
    assert results[0]['method'] == 'POST'
    assert results[0]['url_template'] == '/users'
    assert results[0]['vulnerable'] is True
    
    # Verify the injected properties are present in the JSON body of the result
    body_obj = json.loads(results[0]['request_body'])
    # Should contain one of the BOPLA keys
    assert any(k in body_obj for k in ["isAdmin", "admin", "role", "permission", "is_admin"])
