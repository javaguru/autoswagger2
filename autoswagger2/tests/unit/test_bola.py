# tests/unit/test_bola.py
import pytest
import argparse
import requests
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
