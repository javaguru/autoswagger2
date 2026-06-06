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
