# tests/unit/test_secrets.py
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

    # others patterns
    def test_detect_openai_key(self):
        # OpenAI format: sk-proj-xxxxx or sk-xxxx
        content = "sk-proj-" + "abcdefghijklmnopqrst"
        sensitive, patterns = detect_sensitive_info(content)
        assert sensitive is not None
        assert 'OpenAI API Key' in sensitive

    def test_detect_github_token_modern(self):
        content = "github_pat_" + "1111111111111111111111" + "_" + "11111111111111111111111111111111111111111111111111111111111"
        sensitive, patterns = detect_sensitive_info(content)
        assert sensitive is not None
        assert 'GitHub Token (Modern)' in sensitive

    def test_detect_discord_token(self):
        part1 = "abcdefghijklmnopqrstuvwx"  # 24 chars
        part2 = "abcdef"  # 6 chars
        part3 = "abcdefghijklmnopqrstuvwxyzabcdef"  # 27+ chars
        content = f"{part1}.{part2}.{part3}"
        sensitive, patterns = detect_sensitive_info(content)
        assert sensitive is not None
        assert 'Discord Bot Token' in sensitive

    # masking JWT correctly
    def test_jwt_masking_correct_format(self):
        part1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        part2 = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        part3 = "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        content = "token: " + part1 + "." + part2 + "." + part3

        sensitive, _ = detect_sensitive_info(content)
        assert 'JWT Token' in sensitive
        jwt_val = sensitive['JWT Token'][0]
        # Format should be: header.payload.[REDACTED]
        parts = jwt_val.split('.')
        assert len(parts) == 3
        assert parts[2] == '[REDACTED]'

    # regex patterns compilation
    def test_trufflehog_regexes_compiled(self):
        assert TRUFFLEHOG_REGEXES is not None
        assert len(TRUFFLEHOG_REGEXES) >= 40
        # Check patterns
        assert 'JWT Token' in TRUFFLEHOG_REGEXES
        assert 'AWS API Key' in TRUFFLEHOG_REGEXES
        assert 'Database Connection URI' in TRUFFLEHOG_REGEXES
