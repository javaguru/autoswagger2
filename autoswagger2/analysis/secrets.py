# autoswagger2/analysis/secrets.py
# Manages secret detection using regular expressions.

import re

# --- IMPROVEMENT: TruffleHog key template parsing and tests ---
# Added patterns for modern secrets like JWTs, cloud provider keys, and crypto keys.
TRUFFLEHOG_REGEXES = {
    "Slack Token": r"(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": r"-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "AWS API Key": r"AKIA[0-9A-Z]{16}",
    "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS AppSync GraphQL Key": r"da2-[a-z0-9]{26}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": r"[fF][aA][cC][eE][bB][oO][oO][kK].*['\"]?[0-9a-f]{32}['\"]?",
    "GitHub": r"[gG][iI][tT][hH][uU][bB].*['\"]?[0-9a-zA-Z]{35,40}['\"]?",
    "Generic API Key": r"[aA][pP][iI]_?[kK][eE][yY].*['\"]?[0-9a-zA-Z]{32,45}['\"]?",
    "Generic Secret": r"[sS][eE][cC][rR][eE][tT].*['\"]?[0-9a-zA-Z]{32,45}['\"]?",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google Cloud Platform OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Password in URL": r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}['\"\s]",
    "PayPal Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Telegram Bot API Key": r"[0-9]+:AA[0-9A-Za-z\-_]{33}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twitter Access Token": r"[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth": r"[tT][wW][iI][tT][tT][eE][rR].*['\"]?[0-9a-zA-Z]{35,44}['\"]?",
    "Azure Client Secret": r"[A-Za-z0-9\._~\-]{40}",
    "Google Cloud API Key": r"[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}",
    "Ethereum Private Key": r"0x[0-9a-fA-F]{64}",
    
    # Advanced Patterns
    "JWT Token": r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Private Key (ed25519)": r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",
    "Asymmetric Key (RSA)": r"-----BEGIN RSA PRIVATE KEY-----",
    "API Key (Generic)": r"\b(?:api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?",
    "OpenAI API Key": r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}\b",
    "AWS Secret Access Key": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
    "GitHub Token (Modern)": r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}|gh[pousr]_[a-zA-Z0-9]{36}",
    "Slack Token (Modern)": r"xox[bp]-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}",
    "Discord Bot Token": r"\b[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}\b",
    "Database Connection URI": r"\b(?:postgres|postgresql|mongodb|mysql|redis)://[^/\s:@]+:[^/\s:@]+@.{1,100}\b",
}

# Compile the regexes for performance
COMPILED_TRUFFLEHOG_REGEXES = {name: re.compile(pattern) for name, pattern in TRUFFLEHOG_REGEXES.items()}

# --- IMPROVEMENT: More comprehensive debug info pattern ---
# Now includes common stack trace and database error indicators.
DEBUG_INFO_PATTERN = re.compile(
    r'\b(?:'
    r'env\.[A-Za-z_]+|AWS_[A-Z_]+|AZURE_[A-Z_]+|'  # Environment variables
    r'(?i:DEBUG|ERROR|exception|unknown|stacktrace|traceback)|'  # Common debug keywords (case-insensitive)
    r'Traceback \(most recent call last\)|'  # Python stack trace
    r'SQLSTATE\[\d+]|ORA-\d+|'  # SQL error codes
    r'mysql_fetch_array\(\)|'  # PHP MySQL error
    r'Uncaught exception|'
    r'Internal Server Error'
    r')\b'
)

def detect_sensitive_info(content):
    """
    Searches the response content for known secret patterns (TruffleHog) and debug info patterns.
    Returns a dict of matches if found, along with the regex patterns used.
    """
    sensitive_info = {}
    regex_patterns = {}

    for name, pattern in COMPILED_TRUFFLEHOG_REGEXES.items():
        matches = pattern.findall(content)
        if matches:
            filtered_matches = [match for match in matches if len(set(match)) > 1]
            if filtered_matches:
                if name in ("JWT Token", "JSON Web Token"):
                    masked_matches = []
                    for m in filtered_matches:
                        parts = m.split('.')
                        if len(parts) >= 3:
                            # Mask the JWT signature
                            masked_matches.append(f"{parts[0]}.{parts[1]}.[REDACTED]")
                        else:
                            masked_matches.append(m)
                    sensitive_info.setdefault(name, []).extend(masked_matches)
                else:
                    sensitive_info.setdefault(name, []).extend(filtered_matches)
                regex_patterns[name] = pattern.pattern

    debug_info_found = DEBUG_INFO_PATTERN.findall(content)
    if debug_info_found:
        sensitive_info.setdefault('Debug Information', []).extend(debug_info_found)
        regex_patterns['Debug Information'] = DEBUG_INFO_PATTERN.pattern

    return sensitive_info if sensitive_info else None, regex_patterns
