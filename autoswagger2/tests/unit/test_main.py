# tests/unit/test_main.py
import pytest
import sys
import os
import io
import requests
from unittest.mock import MagicMock, patch
from autoswagger2.__main__ import run

def test_main_arg_parsing_and_orchestration():
    # Test a typical execution flow with mock Scanner
    test_args = ["autoswagger2", "http://localhost:8082/api-docs", "-v", "-rate", "50", "--openapi-version", "3.0.1"]
    
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        
        run()
        
        # Verify Scanner was instantiated and scanner.run() was called
        MockScanner.assert_called_once()
        args_passed = MockScanner.call_args[0]
        # First arg should be urls list
        assert args_passed[0] == ["http://localhost:8082/api-docs"]
        
        parsed_args = args_passed[1]
        assert parsed_args.verbose is True
        assert parsed_args.rate == 50
        assert parsed_args.openapi_version == "3.0.1"

def test_main_empty_urls_exits():
    # Test running without URLs triggers system exit
    with patch.object(sys, 'argv', ["autoswagger2"]), \
         patch('sys.stdin', io.StringIO("")), \
         pytest.raises(SystemExit):
        run()

def test_main_custom_headers_and_user_agent():
    test_args = [
        "autoswagger2", 
        "http://localhost:8082/api-docs", 
        "-H", "X-Custom-Header: value1", 
        "-H", "Authorization: Token xyz",
        "--user-agent", "CustomTester/1.0"
    ]
    
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        
        run()
        
        MockScanner.assert_called_once()
        session_passed = MockScanner.call_args[0][2]
        assert isinstance(session_passed, requests.Session)
        
        # Verify headers were updated correctly
        assert session_passed.headers.get("X-Custom-Header") == "value1"
        assert session_passed.headers.get("Authorization") == "Token xyz"
        assert session_passed.headers.get("User-Agent") == "CustomTester/1.0"

def test_main_api_key_cli_options():
    test_args = [
        "autoswagger2", 
        "http://localhost:8082/api-docs", 
        "--api-key", "secret123",
        "--key-header", "X-API-Key",
        "--key-prefix", "Key "
    ]
    
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        
        run()
        
        MockScanner.assert_called_once()
        session_passed = MockScanner.call_args[0][2]
        assert session_passed.headers.get("X-API-Key") == "Key secret123"

def test_main_api_key_from_file(tmp_path):
    # Create a temporary file containing the token
    token_file = tmp_path / "token.txt"
    token_file.write_text("file_secret_abc")
    
    test_args = [
        "autoswagger2", 
        "http://localhost:8082/api-docs", 
        "--api-key-src", str(token_file),
        "--key-header", "Custom-Auth"
    ]
    
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        
        run()
        
        MockScanner.assert_called_once()
        session_passed = MockScanner.call_args[0][2]
        # Default prefix is "Bearer "
        assert session_passed.headers.get("Custom-Auth") == "Bearer file_secret_abc"


def test_main_tls_verify_enabled_by_default():
    test_args = ["autoswagger2", "http://localhost:8082/api-docs"]
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        run()
        session_passed = MockScanner.call_args[0][2]
        assert session_passed.verify is True


def test_main_insecure_flag_disables_tls_verify():
    test_args = ["autoswagger2", "http://localhost:8082/api-docs", "-k"]
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        run()
        session_passed = MockScanner.call_args[0][2]
        assert session_passed.verify is False


def test_main_allow_external_flag():
    test_args = ["autoswagger2", "http://localhost:8082/api-docs", "--allow-external"]
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        run()
        parsed_args = MockScanner.call_args[0][1]
        assert parsed_args.allow_external is True


def test_main_test_bola_alias():
    test_args = ["autoswagger2", "http://localhost:8082/api-docs", "--test-bola", "--bola-id", "userId=1"]
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        run()
        parsed_args = MockScanner.call_args[0][1]
        assert parsed_args.bola is True
        assert parsed_args.bola_id == "userId=1"


def test_main_threads_cache_and_connection_pool():
    test_args = [
        "autoswagger2",
        "http://localhost:8082/api-docs",
        "-t", "35",
        "--no-cache",
        "--cache-ttl", "120",
    ]
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        run()
        parsed_args = MockScanner.call_args[0][1]
        session_passed = MockScanner.call_args[0][2]

        assert parsed_args.threads == 35
        assert parsed_args.no_cache is True
        assert parsed_args.cache_ttl == 120

        https_adapter = session_passed.get_adapter("https://localhost")
        http_adapter = session_passed.get_adapter("http://localhost")
        assert https_adapter._pool_connections == 35
        assert https_adapter._pool_maxsize == 35
        assert http_adapter._pool_maxsize == 35


def test_main_clamps_threads_and_keeps_min_pool_size():
    test_args = ["autoswagger2", "http://localhost:8082/api-docs", "-t", "500"]
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        run()
        parsed_args = MockScanner.call_args[0][1]
        session_passed = MockScanner.call_args[0][2]
        assert parsed_args.threads == 100
        assert session_passed.get_adapter("https://localhost")._pool_maxsize == 100

    test_args_low = ["autoswagger2", "http://localhost:8082/api-docs", "-t", "0"]
    with patch.object(sys, 'argv', test_args_low), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        run()
        parsed_args = MockScanner.call_args[0][1]
        session_passed = MockScanner.call_args[0][2]
        assert parsed_args.threads == 1
        assert session_passed.get_adapter("https://localhost")._pool_maxsize == 20


def test_main_hidden_and_hidden_wordlist_flags(tmp_path):
    wl = tmp_path / "routes.txt"
    wl.write_text("echo\n", encoding="utf-8")

    # --hidden-wordlist automatically enables args.hidden
    test_args = ["autoswagger2", "http://localhost:8082/nexus-backend", "--hidden-wordlist", str(wl)]
    with patch.object(sys, 'argv', test_args), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        run()
        parsed_args = MockScanner.call_args[0][1]
        assert parsed_args.hidden is True
        assert parsed_args.hidden_wordlist == str(wl)

    # Explicit --hidden without wordlist
    test_args_flag = ["autoswagger2", "http://localhost:8082/nexus-backend", "--hidden"]
    with patch.object(sys, 'argv', test_args_flag), \
         patch('autoswagger2.__main__.Scanner') as MockScanner:
        run()
        parsed_args = MockScanner.call_args[0][1]
        assert parsed_args.hidden is True
        assert parsed_args.hidden_wordlist is None
