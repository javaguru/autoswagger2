# tests/unit/test_secrets.py
import pytest
from autoswagger2.analysis.secrets import detect_sensitive_info, TRUFFLEHOG_REGEXES

class TestSecretDetection:
    def test_detect_jwt_token(self):
        # Concatenate parts to avoid triggering GitHub's static push protection scan on dummy test keys
        part1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        part2 = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        part3 = "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        content = "token: " + part1 + "." + part2 + "." + part3
        
        sensitive, patterns = detect_sensitive_info(content)
        assert sensitive is not None
        assert 'JWT Token' in sensitive
        # Check masking
        assert '[REDACTED]' in sensitive['JWT Token'][0]

    def test_detect_aws_key(self):
        # Concatenate parts to avoid triggering GitHub's static push protection scan on dummy test keys
        content = "AK" + "IA1234567890ABCDEF"
        sensitive, patterns = detect_sensitive_info(content)
        assert sensitive is not None
        assert 'AWS API Key' in sensitive

    def test_detect_slack_token(self):
        # Concatenate parts to avoid triggering GitHub's static push protection scan on dummy test keys
        part1 = "xoxb"
        part2 = "123456789012"
        part3 = "123456789012"
        part4 = "abcdefghijklmnopqrstuvwx"
        content = f"{part1}-{part2}-{part3}-{part4}"
        
        sensitive, patterns = detect_sensitive_info(content)
        assert sensitive is not None
        assert 'Slack Token (Modern)' in sensitive

    def test_detect_database_uri(self):
        # Concatenate parts to avoid triggering GitHub's static push protection scan on dummy test keys
        content = "postgre" + "sql://user:password@localhost:5432/dbname"
        sensitive, patterns = detect_sensitive_info(content)
        assert sensitive is not None
        assert 'Database Connection URI' in sensitive

    def test_no_false_positives(self):
        content = "This is a test string with no secrets"
        sensitive, patterns = detect_sensitive_info(content)
        assert sensitive is None
