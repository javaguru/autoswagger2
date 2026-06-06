# tests/unit/test_bola.py
import pytest
import argparse
import requests
from unittest.mock import MagicMock
from autoswagger2.analysis.bola import BolaTester

def test_generate_neighbor_ids_integer():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BolaTester(args, session)

    neighbors = tester._generate_neighbor_ids("123")
    assert neighbors == ["122", "124"]

def test_generate_neighbor_ids_prefixed_integer():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BolaTester(args, session)

    neighbors = tester._generate_neighbor_ids("usr-123")
    assert neighbors == ["usr-122", "usr-124"]

    neighbors = tester._generate_neighbor_ids("id_99_suffix")
    assert neighbors == ["id_98_suffix", "id_100_suffix"]

def test_generate_neighbor_ids_uuid():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BolaTester(args, session)

    original_uuid = "123e4567-e89b-12d3-a456-426614174000"
    neighbors = tester._generate_neighbor_ids(original_uuid)
    # Should have 3 elements: dec hex, inc hex, and a new random uuid
    assert len(neighbors) == 3
    assert neighbors[0] == "123e4567-e89b-12d3-a456-426614173fff"
    assert neighbors[1] == "123e4567-e89b-12d3-a456-426614174001"
    # The last one should be a valid UUIDv4 string
    assert len(neighbors[2]) == 36

def test_generate_neighbor_ids_mongodb_objectid():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BolaTester(args, session)

    original_id = "507f1f77bcf86cd799439011"
    neighbors = tester._generate_neighbor_ids(original_id)
    assert len(neighbors) == 2
    assert neighbors[0] == "507f1f77bcf86cd799439010"
    assert neighbors[1] == "507f1f77bcf86cd799439012"

def test_generate_neighbor_ids_string_fallback():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BolaTester(args, session)

    neighbors = tester._generate_neighbor_ids("john_doe")
    assert "admin" in neighbors
    assert "guest" in neighbors
    assert "root" in neighbors
    assert "user" in neighbors
    assert "test" in neighbors

def test_compare_responses():
    args = argparse.Namespace(verbose=False)
    session = requests.Session()
    tester = BolaTester(args, session)

    # 1. Matching content and status code 200
    mock_base = MagicMock()
    mock_base.status_code = 200
    mock_base.content = b"A" * 1000

    mock_attack = MagicMock()
    mock_attack.status_code = 200
    mock_attack.content = b"A" * 1000
    assert tester._compare_responses(mock_base, mock_attack) is True

    # 2. Slight difference (5%)
    mock_attack.content = b"A" * 1050
    assert tester._compare_responses(mock_base, mock_attack) is True

    # 3. Large difference (50%)
    mock_attack.content = b"A" * 1500
    assert tester._compare_responses(mock_base, mock_attack) is False

    # 4. Empty baseline, empty attack
    mock_base.content = b""
    mock_attack.content = b""
    assert tester._compare_responses(mock_base, mock_attack) is False

    # 5. Empty baseline, non-empty attack
    mock_attack.content = b"data"
    assert tester._compare_responses(mock_base, mock_attack) is True

    # 6. Status code is not 200
    mock_base.content = b"A" * 1000
    mock_attack.content = b"A" * 1000
    mock_attack.status_code = 403
    assert tester._compare_responses(mock_base, mock_attack) is False

def test_bola_run_tests(monkeypatch):
    args = argparse.Namespace(verbose=False, product=True)
    session = requests.Session()
    tester = BolaTester(args, session)

    endpoints = [{'path': '/users/{userId}', 'method': 'get'}]

    # Case A: Baseline fails (None response)
    monkeypatch.setattr(tester, "_send_request", lambda method, base, path, template, param, obj_id: ("url", None))
    results = tester.run_tests(endpoints, "userId", "123", "http://localhost", "/api")
    assert results == []

    # Case B: Baseline returns 404 (non-200)
    mock_resp_404 = MagicMock()
    mock_resp_404.status_code = 404
    monkeypatch.setattr(tester, "_send_request", lambda method, base, path, template, param, obj_id: ("url", mock_resp_404))
    results = tester.run_tests(endpoints, "userId", "123", "http://localhost", "/api")
    assert results == []

    # Case C: Baseline 200, attack 200 (Vulnerable)
    mock_resp_200 = MagicMock()
    mock_resp_200.status_code = 200
    mock_resp_200.content = b"user profile info"

    mock_attack_200 = MagicMock()
    mock_attack_200.status_code = 200
    mock_attack_200.content = b"user profile info" # similar length

    def mock_send_request(method, api_base, base_path, path, param, object_id):
        if object_id == "123":
            return "url", mock_resp_200
        else:
            return "url", mock_attack_200

    monkeypatch.setattr(tester, "_send_request", mock_send_request)
    results = tester.run_tests(endpoints, "userId", "123", "http://localhost", "/api")
    assert len(results) > 0
    assert results[0]['vulnerable'] is True

