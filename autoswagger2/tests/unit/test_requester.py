# tests/unit/test_requester.py
import pytest
import argparse
import requests
import json
from unittest.mock import MagicMock, patch
from autoswagger2.core.requester import Requester

def get_default_args(**kwargs):
    defaults = {
        "verbose": False,
        "product": False,
        "brute": False,
        "rate": 30,
        "risk": False,
        "all": False,
        "openapi_version": None
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)

def test_generate_parameter_values():
    args = get_default_args()
    session = requests.Session()
    req = Requester("http://localhost", args, session)

    # Test with enum
    assert req._generate_parameter_values("string", ["admin", "user"]) == ["admin", "user"]

    # Test standard types
    assert len(req._generate_parameter_values("integer")) > 0
    assert len(req._generate_parameter_values("string")) > 0
    assert len(req._generate_parameter_values("boolean")) == 2
    assert len(req._generate_parameter_values("number")) > 0
    assert len(req._generate_parameter_values("base64")) > 0
    assert len(req._generate_parameter_values("unknown-type")) > 0

def test_substitute_path_parameters():
    args = get_default_args()
    session = requests.Session()
    req = Requester("http://localhost", args, session)

    params = [
        {"name": "id", "in": "path"},
        {"name": "name", "in": "path"}
    ]
    val_map = {"id": 123, "name": "bob"}

    assert req._substitute_path_parameters("/users/{id}/profile/{name}", params, val_map) == "/users/123/profile/bob"
    assert req._substitute_path_parameters("/users/:id", [{"name": "id", "in": "path"}], {"id": 123}) == "/users/123"
    assert req._substitute_path_parameters("/users/<id>", [{"name": "id", "in": "path"}], {"id": 123}) == "/users/123"
    assert req._substitute_path_parameters("/users/{id}", [{"name": "id", "in": "path"}], {"id": r"\u003Cscript\u003E"}) == r"/users/\u003Cscript\u003E"

def test_generate_query_string():
    args = get_default_args()
    session = requests.Session()
    req = Requester("http://localhost", args, session)

    params = [
        {"name": "limit", "in": "query"},
        {"name": "offset", "in": "query"},
        {"name": "id", "in": "path"} # Should be ignored
    ]
    val_map = {"limit": 10, "offset": 20, "id": 123}

    qs = req._generate_query_string(params, val_map)
    assert "limit=10" in qs
    assert "offset=20" in qs
    assert "id=" not in qs

def test_is_large_response():
    args = get_default_args()
    session = requests.Session()
    req = Requester("http://localhost", args, session)

    # Small content
    assert req._is_large_response("{}") is False

    # Large JSON list
    large_list = json.dumps([i for i in range(100)])
    assert req._is_large_response(large_list) is True

    # Large JSON dict
    large_dict = json.dumps({f"k{i}": i for i in range(100)})
    assert req._is_large_response(large_dict) is True

    # Large XML
    large_xml = "<root>" + "<child></child>" * 101 + "</root>"
    assert req._is_large_response(large_xml) is True

    # Invalid JSON/XML
    assert req._is_large_response("{invalid") is False

def test_build_request_body():
    args = get_default_args()
    session = requests.Session()
    req = Requester("http://localhost", args, session)

    # Empty schema
    assert req._build_request_body(None, "application/json") is None

    # Primitive types
    schema_str = {"type": "string"}
    assert isinstance(json.loads(req._build_request_body(schema_str, "application/json")), str)

    # Dict schema to Form URL Encoded
    schema_obj = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"}
        }
    }
    form_body = req._build_request_body(schema_obj, "application/x-www-form-urlencoded")
    assert "name=" in form_body
    assert "age=" in form_body

    # Dict schema to XML
    xml_body = req._build_request_body(schema_obj, "application/xml")
    assert "<name>" in xml_body or "<root>" in xml_body

    # Plain text
    txt_body = req._build_request_body(schema_str, "text/plain")
    assert isinstance(txt_body, str)

    # Octet stream
    assert req._build_request_body(schema_str, "application/octet-stream") == b'\x00\x01\x02'

    # Multipart file upload
    file_body = req._build_request_body(schema_obj, "multipart/form-data")
    assert "file" in file_body
    assert file_body["file"][0] == "test.txt"

def test_build_nested_object_and_composite():
    args = get_default_args()
    session = requests.Session()
    req = Requester("http://localhost", args, session)

    # Composite schemas: oneOf / anyOf / allOf
    schema_oneof = {
        "oneOf": [
            {"type": "object", "properties": {"opt1": {"type": "string"}}},
            {"type": "object", "properties": {"opt2": {"type": "integer"}}}
        ]
    }
    body_oneof = req._handle_composite_schemas(schema_oneof, 0)
    assert "opt1" in body_oneof

    body_oneof_2 = req._handle_composite_schemas(schema_oneof, 1)
    assert "opt2" in body_oneof_2

    schema_allof = {
        "allOf": [
            {"properties": {"prop1": {"type": "string"}}},
            {"properties": {"prop2": {"type": "integer"}}}
        ]
    }
    body_allof = req._handle_composite_schemas(schema_allof)
    assert "prop1" in body_allof
    assert "prop2" in body_allof

    # Array schema
    schema_arr = {
        "type": "array",
        "items": {"type": "string"}
    }
    body_arr = req._build_request_body(schema_arr, "application/json")
    parsed_arr = json.loads(body_arr)
    assert isinstance(parsed_arr, list)
    assert len(parsed_arr) == 1
    assert isinstance(parsed_arr[0], str)

def test_send_request(monkeypatch):
    args = get_default_args(product=True)
    session = requests.Session()
    req = Requester("http://localhost", args, session)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b'{"status": "ok", "flag": "admin"}'
    mock_resp.headers = {"Content-Type": "application/json"}

    monkeypatch.setattr(session, "request", lambda method, url, **kwargs: mock_resp)

    # Test GET request
    parameters = [{"name": "q", "in": "query"}]
    val_map = {"q": "search_val"}
    response = req._send_request("GET", "http://localhost", "/api/v1/search", parameters, val_map, None, None)

    assert response is not None
    assert response["status_code"] == 200
    assert response["url"] == "http://localhost/api/v1/search?q=search_val"
    assert response["pii_detected"] is False

def test_test_parameter_values(monkeypatch):
    args = get_default_args(brute=False, product=True)
    session = requests.Session()
    req = Requester("http://localhost", args, session)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"content"
    mock_resp.headers = {}

    monkeypatch.setattr(session, "request", lambda method, url, **kwargs: mock_resp)

    parameters = [
        {"name": "id", "in": "query", "type": "integer"},
        {"name": "status", "in": "query", "type": "string"}
    ]

    # Without brute force: should send 1 request
    responses = req._test_parameter_values("GET", "http://localhost", "/api", parameters, None, None)
    assert len(responses) == 1

    # With brute force: one-parameter-at-a-time linear strategy
    args.brute = True
    monkeypatch.setattr(req, "_generate_parameter_values", lambda p_type, enum=None: [1, 2] if p_type == "integer" else ["a", "b"])
    
    responses_brute = req._test_parameter_values("GET", "http://localhost", "/api", parameters, None, None)
    # 1 baseline + (2-1) for id + (2-1) for status = 3 requests
    assert len(responses_brute) == 3

    # With 4 parameters x 5 values: 1 + 4*(5-1) = 17 requests instead of 5^4 = 625
    four_params = [{"name": f"p{i}", "in": "query", "schema": {"type": "string", "enum": ["v1", "v2", "v3", "v4", "v5"]}} for i in range(4)]
    monkeypatch.setattr(req, "_generate_parameter_values", lambda p_type, enum=None: enum if enum else ["default"])
    responses_four = req._test_parameter_values("GET", "http://localhost", "/api", four_params, None, None)
    assert len(responses_four) == 17


def test_build_request_body_recursive_cyclic_ref_and_nested_array():
    args = get_default_args()
    session = requests.Session()
    req = Requester("http://localhost", args, session)

    spec = {
        "components": {
            "schemas": {
                "Address": {
                    "type": "object",
                    "properties": {"city": {"type": "string", "enum": ["Paris"]}}
                },
                "Meta": {
                    "type": "object",
                    "properties": {"tag": {"type": ["string", "null"]}}
                },
                "Combined": {
                    "allOf": [
                        {"$ref": "#/components/schemas/Address"},
                        {"$ref": "#/components/schemas/Meta"}
                    ]
                },
                "Node": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string"},
                        "address": {"$ref": "#/components/schemas/Address"},
                        "combined": {"$ref": "#/components/schemas/Combined"},
                        "items": {"type": "array", "items": {"$ref": "#/components/schemas/Address"}},
                        "children": {"type": "array", "items": {"$ref": "#/components/schemas/Node"}},
                        "parent": {"$ref": "#/components/schemas/Node"}
                    }
                }
            }
        }
    }
    body_json = req._build_request_body({"$ref": "#/components/schemas/Node"}, "application/json", spec_data=spec)
    parsed = json.loads(body_json)
    assert parsed["address"] == {"city": "Paris"}
    assert parsed["combined"]["city"] == "Paris"
    assert isinstance(parsed["combined"]["tag"], str)
    assert parsed["items"] == [{"city": "Paris"}]
    assert parsed["children"] == []
    assert "parent" not in parsed

    arr_json = req._build_request_body({"type": "array", "items": {"$ref": "#/components/schemas/Address"}}, "application/json", spec_data=spec)
    assert json.loads(arr_json) == [{"city": "Paris"}]


def test_detect_response_anomalies():
    args = get_default_args()
    req = Requester("http://localhost", args, requests.Session())

    assert "Potential File Disclosure (LFI)" in req._detect_response_anomalies("root:x:0:0:root:/root:/bin/bash", "text/plain")
    assert "SQL/Database Error Leak" in req._detect_response_anomalies("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server", "application/json")
    assert "Reflected HTML/XSS Indicator" in req._detect_response_anomalies(
        "<html><body>Hello <script>alert(1)</script></body></html>",
        "text/html",
        {"q": "<script>alert(1)</script>"}
    )
    assert req._detect_response_anomalies('{"error": null, "status": "ok"}', "application/json") == []

def test_test_webhook_and_endpoint(monkeypatch):
    args = get_default_args(verbose=True, product=True, allow_external=False)
    session = requests.Session()
    session.headers["Authorization"] = "Bearer secret-token"
    req = Requester("http://localhost", args, session)

    captured_calls = []
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"ok"
    mock_resp.headers = {}

    def mock_request(method, url, **kwargs):
        captured_calls.append((method, url, kwargs.get("headers", {})))
        return mock_resp

    monkeypatch.setattr(session, "request", mock_request)

    # Test webhook skipping runtime variables
    results = req._test_webhook("{$request.body#/callbackUrl}", "POST", [], "/api", None, None, "test_hook")
    assert results == []

    # Test same-origin full URL webhook
    results_same_origin = req._test_webhook("http://localhost/receiver", "POST", [], "/api", None, None, "test_hook")
    assert len(results_same_origin) == 1
    assert results_same_origin[0]["url"] == "http://localhost/receiver"

    # Test external webhook blocked by default
    results_ext_blocked = req._test_webhook("http://callback.com/receiver", "POST", [], "/api", None, None, "test_hook")
    assert results_ext_blocked == []

    # Test external webhook allowed with --allow-external strips sensitive session headers
    args.allow_external = True
    captured_calls.clear()
    results_ext_allowed = req._test_webhook("http://callback.com/receiver", "POST", [], "/api", None, None, "test_hook")
    assert len(results_ext_allowed) == 1
    assert results_ext_allowed[0]["url"] == "http://callback.com/receiver"
    assert captured_calls[0][2].get("Authorization") is None
    assert "Authorization" in captured_calls[0][2]

    # Test normal endpoint wrapper
    results_ep = req._test_endpoint("/users", "GET", [], "/api", None, None)
    assert len(results_ep) == 1


def test_root_base_path_url_building(monkeypatch):
    args = get_default_args(product=True)
    session = requests.Session()
    req = Requester("http://localhost:8080", args, session)

    called_urls = []
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"ok"
    mock_resp.headers = {}

    def mock_request(method, url, **kwargs):
        called_urls.append(url)
        return mock_resp

    monkeypatch.setattr(session, "request", mock_request)

    params = [{"name": "id", "in": "path", "type": "integer"}]
    results = req._test_endpoint("/users/{id}", "GET", params, "/", None, None)
    assert len(results) == 1
    assert called_urls == ["http://localhost:8080/users/1"]

def test_test_endpoints_orchestration(monkeypatch):
    args = get_default_args(risk=True, product=True)
    session = requests.Session()
    req = Requester("http://localhost", args, session)

    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/users": {
                "get": {
                    "operationId": "getUsers",
                    "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}]
                },
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object", "properties": {"name": {"type": "string"}}}
                            }
                        }
                    }
                }
            }
        }
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"response"
    mock_resp.headers = {}
    monkeypatch.setattr(session, "request", lambda *a, **kw: mock_resp)

    results = req.test_endpoints(spec, "/api")
    # Should test GET /users and POST /users
    assert len(results) >= 2
