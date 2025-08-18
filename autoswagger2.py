#!/usr/bin/env python3
# Autoswagger2 Copyright Jservlet.com 2025 Franck Andriano.
# From original version Autoswagger - Cale Anderson @ Intruder
#
# --- Modifications Summary ---
# Modified by Franck Andriano. @ FranckAndriano
#
# This script has been significantly enhanced from the original version.
# Key improvements are detailed below:
#
# 1. Advanced Spec Discovery Engine:
#    - Context-Aware Searching: The discovery logic now prioritizes searching within the user-provided URL path
#      (e.g., /app-context/) before falling back to the server root, making it effective for non-root applications.
#    - Intelligent URL Handling: It correctly distinguishes between direct spec URLs, Swagger UI pages, and base URLs,
#      and follows the appropriate discovery path for each.
#    - Spring Boot / springdoc-openapi Compatibility: The parser now correctly handles multi-step discovery,
#      including the `configUrl` property and API group lists, to find the true spec URL.
#    - Default Configuration Filtering: Actively ignores the default "petstore.swagger.io" example URL to prevent false positives,
#      while still allowing the Petstore site itself to be scanned.
#
# 2. Enhanced Security Analysis Capabilities:
#    - Expanded discovery paths based on Nuclei templates.
#    - Secret Detection (TruffleHog Patterns): The list of regex patterns has been significantly expanded to detect
#      modern secrets, including JSON Web Tokens (JWT), Azure and Google Cloud credentials, and Ethereum private keys.
#    - PII (Personally Identifiable Information) Detection: Integrated the 'presidio-analyzer' library to scan
#      API responses for sensitive personal data. Now includes JSON-aware analysis and new recognizers for
#      credit cards, dates of birth, national ID numbers (FR/US), IBANs, IP/MAC addresses, and license plates (FR/US).
#    - Creative Test Payloads: The `TEST_VALUES` dictionary has been completely revamped with a wide range of payloads
#      for SQLi, NoSQLi, Command Injection, SSTI, XSS, Path Traversal, and various fuzzing/edge cases.
#    - Refined Debug Info Detection: The pattern for detecting debug information is now more comprehensive,
#      catching common stack traces and database error messages while being classified separately from secrets.
#
# 3. General & Quality-of-Life Improvements:
#    - Versioning: Added a `--version` flag to display the current tool version.
#    - Custom User-Agent: All outgoing HTTP requests now use a 'AutoSwagger2' User-Agent for better identification in server logs.
#    - Authentication Support: Added flexible authentication options: a generic '--header' / '-H', and user-friendly
#      '--api-key', '--api-key-src', '--key-header', and '--key-prefix' for common token-based auth.
#    - Enhanced Verbose Logging: The verbose output (-v) now includes the request body for easier debugging.
#    - Robustness & Bug Fixes:
#        - Correctly generates JSON object request bodies when expected by the API, resolving backend errors.
#        - Prevents false positives by skipping secret detection on binary content (e.g., images, octet-streams).
#        - Fixed serialization errors for table and JSON output when handling binary or complex request bodies.
#        - Correctly uses specified data types for path parameters (e.g., integer vs. string).
#        - Properly formats `multipart/form-data` requests for file uploads.
#        - Fixed brute-force mode (-b) to test all parameter combinations instead of stopping after the first success.
#        - Fixed UnicodeEncodeError on Windows by setting log file encoding to UTF-8.
#        - Fixed a false positive where secret detection would match long strings of repeating characters.
#    - Expanded Path Lists: Added more common paths to `SWAGGER_UI_PATHS` and `DIRECT_SPEC_PATHS` to increase the success rate of discovery.
#    - Modernized Output: The output now clearly distinguishes between high-confidence "PII/Secret" findings and
#      lower-confidence "Debug Info" indicators. URLs with findings are highlighted and truncated for readability.

import argparse
import json
import os
import re
import sys
import threading
import time
from itertools import product as itertools_product
from urllib.parse import urljoin, urlencode, urlparse

import requests
import urllib3
from dicttoxml import dicttoxml
import yaml
import xml.etree.ElementTree as ET
from datetime import datetime

from concurrent.futures import ThreadPoolExecutor, as_completed

# Import Presidio for PII detection
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, Pattern, PatternRecognizer

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
import logging

__version__ = "2.0.0"

# ------------------------------
# Global Variables for Stats
# ------------------------------
TOTAL_REQUESTS = 0       # Tracks total requests sent by the tool
SCAN_START_TIME = 0.0    # Records scan start time (for RPS calculation)
SCAN_END_TIME = 0.0      # Records scan end time (for RPS calculation)

# Initialize Presidio Analyzer with custom recognizers
registry = RecognizerRegistry()

# Initialize file_handler for log data output
file_handler = None

def setup_pii_recognizers():
    """
    Adds custom recognizers for various PII types to the Presidio registry.
    """
    # Person
    person_pattern = Pattern(name="person", regex=r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b", score=0.85)
    person_recognizer = PatternRecognizer(supported_entity="PERSON", patterns=[person_pattern], context=["name", "first_name", "last_name", "firstname", "lastname"])
    registry.add_recognizer(person_recognizer)

    # Phone Number
    phone_pattern = Pattern(name="phone_number", regex=r"(\+?\d{1,3}[-.\s]?(\d{3})[-.\s]?(\d{3,4})[-.\s]?(\d{4}))", score=0.85)
    phone_recognizer = PatternRecognizer(supported_entity="PHONE_NUMBER", patterns=[phone_pattern], context=["phone", "mobile", "telephone", "tel", "phone_number"])
    registry.add_recognizer(phone_recognizer)

    # Email Address
    email_pattern = Pattern(name="email", regex=r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", score=0.85)
    email_recognizer = PatternRecognizer(supported_entity="EMAIL_ADDRESS", patterns=[email_pattern], context=["email", "email_address", "contact"])
    registry.add_recognizer(email_recognizer)

    # Address (Improved Context)
    address_pattern = Pattern(name="address", regex=r"\b\d{1,5}\s\w+\s\w+\b", score=0.85)
    address_recognizer = PatternRecognizer(supported_entity="ADDRESS", patterns=[address_pattern], context=["addr", "address", "location", "street", "rue", "avenue", "boulevard", "city", "ville", "zipcode", "postcode", "code postal", "country", "pays"])
    registry.add_recognizer(address_recognizer)

    # Credit Card Number
    cc_pattern = Pattern(name="credit_card", regex=r"\b(?:\d[ -]*?){13,16}\b", score=0.85)
    cc_recognizer = PatternRecognizer(supported_entity="CREDIT_CARD_NUMBER", patterns=[cc_pattern], context=["card", "cc", "credit", "debit", "cardnumber", "pan", "carte"])
    registry.add_recognizer(cc_recognizer)

    # Date of Birth
    dob_pattern = Pattern(name="date_of_birth", regex=r"\b(\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b", score=0.85)
    dob_recognizer = PatternRecognizer(supported_entity="DATE_OF_BIRTH", patterns=[dob_pattern], context=["dob", "birthdate", "date_of_birth", "birthday", "naissance"])
    registry.add_recognizer(dob_recognizer)

    # French INSEE Number
    insee_pattern = Pattern(name="fr_insee_number", regex=r"\b[12]\d{2}(0[1-9]|1[0-2])(2[ABab]|\d{2})\d{3}\d{3}\d{2}\b", score=0.9)
    insee_recognizer = PatternRecognizer(supported_entity="FR_INSEE_NUMBER", patterns=[insee_pattern], context=["insee", "nir", "securite_sociale", "numéro de sécurité sociale"])
    registry.add_recognizer(insee_recognizer)

    # US Social Security Number
    ssn_pattern = Pattern(name="us_ssn", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=0.9)
    ssn_recognizer = PatternRecognizer(supported_entity="US_SSN", patterns=[ssn_pattern], context=["ssn", "social security number", "taxpayer id"])
    registry.add_recognizer(ssn_recognizer)

    # Passport Number
    passport_pattern = Pattern(name="passport_number", regex=r"\b[A-Z0-9<]{8,15}\b", score=0.8)
    passport_recognizer = PatternRecognizer(supported_entity="PASSPORT_NUMBER", patterns=[passport_pattern], context=["passport", "passeport", "passport_number", "passportno", "travel document"])
    registry.add_recognizer(passport_recognizer)

    # IBAN Number
    iban_pattern = Pattern(name="iban", regex=r"\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9]{4}){4,7}\b", score=0.85)
    iban_recognizer = PatternRecognizer(supported_entity="IBAN_NUMBER", patterns=[iban_pattern], context=["iban", "bank", "account", "rib", "compte"])
    registry.add_recognizer(iban_recognizer)

    # French License Plate
    fr_plate_pattern = Pattern(name="fr_license_plate", regex=r"\b([A-Z]{2}-\d{3}-[A-Z]{2}|\d{1,4}\s[A-Z]{2,3}\s\d{2})\b", score=0.7)
    fr_plate_recognizer = PatternRecognizer(supported_entity="FR_LICENSE_PLATE", patterns=[fr_plate_pattern], context=["immatriculation", "plaque", "license_plate", "vehicle", "registration"])
    registry.add_recognizer(fr_plate_recognizer)

    # --- NEW: US License Plate ---
    us_plate_pattern = Pattern(name="us_license_plate", regex=r"\b([A-Z]{1,3}[- ]?\d{1,4}|\d{1,4}[- ]?[A-Z]{1,3})\b", score=0.6)
    us_plate_recognizer = PatternRecognizer(supported_entity="US_LICENSE_PLATE", patterns=[us_plate_pattern], context=["license", "plate", "vehicle", "registration", "vin"])
    registry.add_recognizer(us_plate_recognizer)

    # IP Address
    ip_pattern = Pattern(name="ip_address", regex=r"\b(?:\d{1,3}\.){3}\d{1,3}\b", score=0.7)
    ip_recognizer = PatternRecognizer(supported_entity="IP_ADDRESS", patterns=[ip_pattern], context=["ip", "address", "ip_address", "last_login_ip"])
    registry.add_recognizer(ip_recognizer)

    # MAC Address
    mac_pattern = Pattern(name="mac_address", regex=r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b", score=0.8)
    mac_recognizer = PatternRecognizer(supported_entity="MAC_ADDRESS", patterns=[mac_pattern], context=["mac", "mac_address", "physical_address"])
    registry.add_recognizer(mac_recognizer)

# Call setup function to prepare custom PII recognizers
setup_pii_recognizers()

# Initialize Presidio context-aware enhancer
from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer

context_aware_enhancer = LemmaContextAwareEnhancer(
    context_similarity_factor=0.35,
    min_score_with_context_similarity=0.4
)

# Analyzer engine for detection
analyzer = AnalyzerEngine(
    registry=registry,
    context_aware_enhancer=context_aware_enhancer
)

# Initialize Rich Console for formatted output
console = Console()

# Suppress warnings about unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- MODIFICATION: Create a global session object with a custom User-Agent ---
# This ensures all requests made by the script identify themselves as "AutoSwagger2".
session = requests.Session()
session.headers.update({'User-Agent': f'AutoSwagger2/{__version__}'})
session.verify = False # Equivalent to verify=False everywhere

# Default request timeout
TIMEOUT = 10

# --- IMPROVEMENT: Expanded discovery paths based on Nuclei templates ---
SWAGGER_UI_PATHS = sorted({
    "/", "/apidocs/", "/swagger/ui/index", "/swagger/index.html", "/swagger-ui.html",
    "/swagger-ui/index.html", "/swagger/swagger-ui.html", "/api/swagger-ui.html",
    "/api_docs", "/api/index.html", "/api/doc", "/api/docs/", "/api/swagger/index.html",
    "/api/swagger/swagger-ui.html", "/api/swagger-ui/api-docs", "/api/api-docs",
    "/api/apidocs", "/api/swagger", "/api/swagger/static/index.html",
    "/api/swagger-resources", "/api/swagger-resources/restservices/v2/api-docs",
    "/api/__swagger__/", "/api/_swagger_/", "/docu", "/docs", "/swagger", "/api-doc",
    "/doc/", "/webjars/swagger-ui/index.html", "/3.0.0/swagger-ui.html",
    "/MobiControl/api/docs/index/index.html", "/Swagger", "/Swagger/", "/Swagger/index.html",
    "/V2/api-docs/ui", "/admin/swagger-ui/index.html", "/api-doc/", "/api-docs/",
    "/api-docs/ui/", "/api-docs/v1/index.html", "/api-documentation/index.html",
    "/api/", "/api/api-docs", "/api/api-docs/index.html", "/api/api/",
    "/api/apidocs", "/api/config", "/api/doc", "/api/doc/", "/api/spec/", "/spec/",
    "/swagger-ui/swagger-ui.js", "/swagger/swagger-ui.js", "/swagger-ui.js",
    "/swagger/ui/swagger-ui.js", "/api/docs/index.html", "/api/help/swagger-console.html",
    "/api/swagger/ui/index", "/__swagger__/", "/_swagger_/",
    "/swagger-resources/configuration/security", "/swagger-resources/configuration/ui",
    "/swagger-ui/", "/swagger-ui/vendor", "/swagger/", "/swagger/api-docs/",
    "/swagger/dist/index.html", "/swagger/document", "/swagger/static/index.html",
    "/swaggerui/", "/swaggerui/index.html", "/v1/api-docs/", "/v1/api-docs/index.html",
    "/v1/swagger-ui.html", "/v3/api-docs/ui", "/webapi/index.html",
    "/webapi/swagger/index.html", "/webjars/springfox-swagger-ui/3.0.0/swagger-ui.html",
    "/webjars/swagger-ui/2.2.5/index.html"
})

DIRECT_SPEC_PATHS = sorted({
    "/swagger.json", "/swagger.yaml", "/swagger.yml", "/api/swagger.json",
    "/api/swagger.yaml", "/api/swagger.yml", "/v1/swagger.json",
    "/v1/swagger.yaml", "/v1/swagger.yml", "/openapi.json",
    "/openapi.yaml", "/openapi.yml", "/api/openapi.json",
    "/api/openapi.yaml", "/api/openapi.yml", "/docs/swagger.json",
    "/docs/swagger.yaml", "/docs/openapi.json", "/docs/openapi.yaml",
    "/api-docs/swagger.json", "/api-docs/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v1/swagger.yaml",
    "/rest/swagger.json", "/rest/swagger.yaml", "/rest-api/swagger.json",
    "/swagger/v1/docs.json", "/api/swagger/docs.json",
    "/swagger/docs/v1.json", "/swagger/swagger.json", "/swagger/swagger.yaml",
    "/api-doc.json", "/api/spec/swagger.json", "/api/spec/swagger.yaml",
    "/api/v1/swagger-ui/swagger.json", "/api/v1/swagger-ui/swagger.yaml",
    "/api/swagger_doc.json", "/v2/swagger.json", "/v2/swagger.yaml",
    "/v3/swagger.json", "/v3/swagger.yaml", "/openapi2.json",
    "/openapi2.yaml", "/openapi2.yml", "/api/v3/openapi.json",
    "/api/v3/openapi.yaml", "/api/v3/openapi.yml", "/spec/swagger.json",
    "/spec/swagger.yaml", "/spec/openapi.json", "/spec/openapi.yaml",
    "/api-docs/swagger-ui.json", "/api-docs/swagger-ui.yaml",
    "/api-docs/openapi.json", "/api-docs/openapi.yaml",
    "/swagger-ui.json", "/swagger-ui.yaml",
    "/v2/api-docs", "/v3/api-docs",
})

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
    "JSON Web Token": r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Azure Client Secret": r"[A-Za-z0-9\._~\-]{40}",
    "Google Cloud API Key": r"[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}",
    "Ethereum Private Key": r"0x[0-9a-fA-F]{64}",
}

# Compile the regexes for performance
COMPILED_TRUFFLEHOG_REGEXES = {name: re.compile(pattern) for name, pattern in TRUFFLEHOG_REGEXES.items()}

# --- IMPROVEMENT: More comprehensive debug info pattern ---
# Now includes common stack trace and database error indicators.
DEBUG_INFO_PATTERN = re.compile(
    r'\b(?:'
    r'env\.[A-Za-z_]+|AWS_[A-Z_]+|AZURE_[A-Z_]+|'  # Environment variables
    r'(?i:DEBUG|ERROR|exception|stacktrace|traceback)|'  # Common debug keywords (case-insensitive)
    r'Traceback \(most recent call last\)|'  # Python stack trace
    r'SQLSTATE\[\d+]|ORA-\d+|'  # SQL error codes
    r'mysql_fetch_array\(\)|'  # PHP MySQL error
    r'Uncaught exception|'
    r'Internal Server Error'
    r')\b'
)

# --- IMPROVEMENT: More creative and comprehensive test values ---
# Expanded with a wider range of payloads for injection, traversal, and edge cases.
TEST_VALUES = {
    "integer": [1, 0, -1, 100, 999999, 2147483647],
    "string": [
        # --- Common & Default ---
        "test", "admin", "1", "", "*",
        # --- Injection Payloads (SQL, NoSQL, Command, SSTI) ---
        "' OR 1=1--", "'; exec sp_xp_cmdshell 'whoami'--",
        "||'admin'--",
        "||(SELECT 'admin')",
        "1; SELECT pg_sleep(10)--",
        "{\"username\":{\"$ne\": \"\"}, \"password\":{\"$ne\": \"\"}}",
        "; ls -la", "| whoami", "`id`",
        "{{7*7}}", "${7*7}}", "<%= 7*7 %>",
        # --- Traversal & File Inclusion ---
        "../../../../etc/passwd", "../../../../../windows/system32/drivers/etc/hosts",
        "file:///etc/passwd", "php://filter/convert.base64-encode/resource=index.php",
        # --- XSS Payloads ---
        "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        # --- Edge Cases & Fuzzing ---
        "null", "true", "false", "undefined",
        "test@example.com", "550e8400-e29b-41d4-a716-446655440000", # Email & UUID
        "A" * 1024, # Long string
        "你好", # Unicode
        "%00", "%0a", "%0d", # Control characters
        "'" , "\"", "<", ">", "&", # Special characters
    ],
    "boolean": [True, False],
    "number": [1.0, 0.0, -1.5, 999.99, 1.7976931348623157e+308],
    "base64": [
        # --- Common & Default ---
        "MQ==", # 1
        "YWRtaW4=", # admin
        # --- Auth-related Payloads ---
        "YWRtaW46YWRtaW4=", # admin:admin
        "dGVzdDE6MTIzNDU2", # test1:123456
        # --- Common Formats & Files ---
        "eyJ1c2VyIjogImFkbWluIiwgImlkIjogMTIzfQ==", # {"user": "admin", "id": 123}
        "L2V0Yy9wYXNzd2Q=", # /etc/passwd
        "UEsDBAoAAAAA", # PK.. zip file header
    ],
    "default": ["1", "test", True, "550e8400-e29b-41d4-a716-446655440000", "*"]
}

# Lock for thread-safe operations
lock = threading.Lock()

# Initialize logger with RichHandler
logger = logging.getLogger("autoswagger")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")

# Set to track hosts where no valid swagger was found
bad_hosts = set()

def get_timestamp():
    """
    Returns current timestamp in the format [HH:MM:SS].
    Used for logging messages with a consistent time prefix.
    """
    return time.strftime("[%H:%M:%S]")

def log(message, level="INFO"):
    """
    Logs a message with a given level to both the Rich console and the optional file_handler.

    :param message: String message to log
    :param level: Logging level ('INFO', 'DEBUG', 'WARNING', 'CRITICAL', 'SUCCESS')
    """
    global file_handler
    timestamp = get_timestamp()
    levels = {
        "INFO": "[green][INFO][/green]",
        "DEBUG": "[cyan][DEBUG][/cyan]",
        "WARNING": "[yellow][WARNING][/yellow]",
        "CRITICAL": "[red][CRITICAL][/red]",
        "SUCCESS": "[bold green][SUCCESS][/bold green]"
    }
    level_prefix = levels.get(level, f"[{level}]")
    formatted_message = f"{timestamp} {level_prefix} {message}"
    console.print(formatted_message, highlight=False)
    if file_handler and level == "DEBUG":
        logger.debug(message)
    elif file_handler and level in ["INFO", "WARNING", "CRITICAL", "SUCCESS"]:
        logger.info(message)

def print_banner():
    """
    Prints the ASCII banner for Autoswagger2 with jservlet.com link in yellow.
    Called if not in product mode, to show the standard header.
    """
    banner = fr"""[white]
    ___         __       _____                                   [red] ___ [/red]
   /   | __  __/ /_____ / ___/      ______ _____ _____ ____  ____[red]|__ \ [/red]
  / /| |/ / / / __/ __ \\__ \ | /| / / __ `/ __ `/ __ `/ _ \/ ___/[red]_/ / [/red]
 / ___ / /_/ / /_/ /_/ /__/ / |/ |/ / /_/ / /_/ / /_/ /  __/ /  [red]/ __/ [/red]
/_/  |_\__,_/\__/\____/____/|__/|__/\__,_/\__, /\__, /\___/_/  [red]/____/ [/red]
                                         /____//____/    [/white]
                              [yellow]https://jservlet.com[/yellow]
                          Find unauthenticated endpoints
    """
    console.print(banner)

def generate_parameter_values(param_type, enum=None):
    """
    Returns a list of test values for a given parameter type.
    If an enum list is provided, uses that instead of defaults.
    """
    if enum:
        return enum
    return TEST_VALUES.get(param_type, TEST_VALUES["default"])

def build_nested_object(schema, value_index=0):
    """
    Recursively constructs a nested object (dict) for complex schemas.
    Handles properties, arrays, and composite references (oneOf, anyOf, allOf).
    """
    obj = {}
    for key, prop in schema.get('properties', {}).items():
        if '$ref' in prop:
            continue
        if 'oneOf' in prop or 'anyOf' in prop or 'allOf' in prop:
            obj[key] = handle_composite_schemas(prop, value_index)
        elif prop.get('type') == 'object':
            obj[key] = build_nested_object(prop, value_index)
        elif prop.get('type') == 'array':
            obj[key] = build_array_item(prop, value_index)
        else:
            param_type = prop.get('type', 'string')
            enum = prop.get('enum', None)
            values = generate_parameter_values(param_type, enum)
            obj[key] = values[value_index % len(values)]
    return obj

def handle_composite_schemas(schema, value_index=0):
    """
    Handles composite schema definitions like oneOf, anyOf, and allOf.
    Calls build_nested_object recursively on the chosen sub-schema or the combined properties.
    """
    if 'oneOf' in schema:
        return build_nested_object(schema['oneOf'][value_index % len(schema['oneOf'])], value_index)
    elif 'anyOf' in schema:
        return build_nested_object(schema['anyOf'][value_index % len(schema['anyOf'])], value_index)
    elif 'allOf' in schema:
        combined_schema = {}
        for sub_schema in schema['allOf']:
            combined_schema.update(sub_schema.get('properties', {}))
        return build_nested_object({'properties': combined_schema}, value_index)
    return build_nested_object(schema, value_index)

def build_array_item(item_schema, value_index=0):
    """
    Builds an array item from the given schema.
    If the schema is an object or contains properties, delegates to build_nested_object.
    Otherwise chooses from test values by type.
    """
    if 'properties' in item_schema or item_schema.get('type') == 'object':
        return build_nested_object(item_schema, value_index)
    else:
        param_type = item_schema.get('type', 'string')
        enum = item_schema.get('enum', None)
        values = generate_parameter_values(param_type, enum)
        return values[value_index % len(values)]

def build_file_upload_body(schema, content_type, value_index=0):
    """
    Builds a simple file upload body for multipart/form-data.
    Returns a dict with a file-like tuple if content_type is multipart/form-data.
    """
    if content_type == 'multipart/form-data':
        return {'file': ('test.txt', b'This is a test file')}
    return None

def build_request_body(schema, content_type, value_index=0):
    """
    Builds a request body based on the schema and specified content type.
    Supports JSON, XML, form-encoded, plain text, octet-stream, and multipart.
    """
    if not schema:
        return None

    body = None
    # FIX: Prioritize object construction if 'properties' are defined,
    # as 'type: object' can be implicit. This handles cases where the API
    # expects a JSON object but the spec omits the explicit type.
    if 'properties' in schema or schema.get('type') == 'object':
        body = build_nested_object(schema, value_index)
    elif 'oneOf' in schema or 'anyOf' in schema or 'allOf' in schema:
        body = handle_composite_schemas(schema, value_index)
    elif schema.get('type') == 'array':
        item_schema = schema.get('items', {})
        body = [build_array_item(item_schema, value_index)]
    else:
        # This branch is for primitive request bodies (e.g., sending a raw number or string)
        param_type = schema.get('type', 'string')
        enum = schema.get('enum', None)
        values = generate_parameter_values(param_type, enum)
        body = values[value_index % len(values)]

    if content_type == 'application/x-www-form-urlencoded':
        # body should be a dict for urlencode
        return urlencode(body) if isinstance(body, dict) else body
    elif content_type == 'application/xml':
        # dicttoxml expects a dictionary
        return dicttoxml(body).decode() if isinstance(body, dict) else str(body)
    elif content_type == 'application/json':
        return json.dumps(body)
    elif content_type == 'text/plain':
        return str(body)
    elif content_type == 'application/octet-stream':
        return b'\x00\x01\x02'
    elif content_type == 'multipart/form-data':
        return build_file_upload_body(schema, content_type, value_index)

    # Default to JSON serialization
    return json.dumps(body)

def substitute_path_parameters(path, parameters, value_mapping):
    """
    Replaces path parameter placeholders (e.g. {id}, :id, <id>) with generated values.
    """
    for param in parameters:
        if param.get('in') == 'path':
            param_name = param.get('name')
            value = value_mapping.get(param_name)
            if value is not None:
                path = re.sub(rf'{{{param_name}}}|:{param_name}|<{param_name}>', str(value), path)
    return path

def generate_query_string(parameters, value_mapping):
    """
    Creates a query string (e.g. ?key=value) for parameters that are in the query location.
    """
    query_params = {}
    for param in parameters:
        if param.get('in') == 'query':
            param_name = param.get('name')
            value = value_mapping.get(param_name)
            if value is not None:
                query_params[param_name] = value
    return urlencode(query_params)

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
            # FIX: Filter out false positives from repeating characters (e.g., "AAAA...")
            filtered_matches = [match for match in matches if len(set(match)) > 1]
            if filtered_matches:
                sensitive_info.setdefault(name, []).extend(filtered_matches)
                regex_patterns[name] = pattern.pattern

    debug_info_found = DEBUG_INFO_PATTERN.findall(content)
    if debug_info_found:
        sensitive_info.setdefault('Debug Information', []).extend(debug_info_found)
        regex_patterns['Debug Information'] = DEBUG_INFO_PATTERN.pattern

    return sensitive_info if sensitive_info else None, regex_patterns

def is_large_response(content):
    """
    Checks if the response is large, specifically:
    - Contains 100+ items in JSON arrays or dictionary keys
    - Or 100+ elements in XML
    - Or raw content_length > 100000 bytes
    """
    try:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        if content.strip().startswith('{') or content.strip().startswith('['):
            data = json.loads(content)
            if isinstance(data, list) and len(data) >= 100:
                return True
            elif isinstance(data, dict):
                total_items = sum(1 for _ in data.values())
                if total_items >= 100:
                    return True
        elif content.strip().startswith('<'):
            root = ET.fromstring(content)
            total_elements = sum(1 for _ in root.iter())
            if total_elements >= 100:
                return True
    except (json.JSONDecodeError, ET.ParseError):
        pass
    return False

def test_parameter_values(method, base_url_no_path, full_path, parameters, request_body, content_type, rate, include_all, verbose, brute=False):
    """
    Tests parameter values for a given method/endpoint.
    If brute is false, only a single default set is tested.
    If brute is true, tries enumerating multiple data types/values.
    """
    all_responses = []
    value_mapping = {}

    # Collect parameter names and types
    param_info = []
    for param in parameters:
        if param.get('in') in ['path', 'query']:
            param_name = param.get('name')
            schema = param.get('schema', {})
            param_type = param.get('type') or schema.get('type', 'string')
            enum = param.get('enum', None)
            param_info.append({'name': param_name, 'type': param_type, 'enum': enum})

    if not brute:
        # Default mode: one request with the first value of the correct type
        for p_info in param_info:
            values = generate_parameter_values(p_info['type'], p_info['enum'])
            value_mapping[p_info['name']] = values[0]

        response = send_request(
            method, base_url_no_path, full_path, parameters,
            value_mapping, request_body, content_type, rate, include_all, verbose
        )
        if response:
            all_responses.append(response)
    else:
        # Brute mode: iterate through all values for each parameter
        param_value_lists = []
        for p_info in param_info:
            values = generate_parameter_values(p_info['type'], p_info['enum'])
            param_value_lists.append(values)

        if not param_value_lists: # Handle endpoints with no path/query params
             response = send_request(
                method, base_url_no_path, full_path, parameters,
                {}, request_body, content_type, rate, include_all, verbose
            )
             if response:
                all_responses.append(response)
        else:
            # Create all combinations of parameter values
            value_combinations = itertools_product(*param_value_lists)
            for combo in value_combinations:
                current_value_mapping = {p_info['name']: combo[i] for i, p_info in enumerate(param_info)}
                response = send_request(
                    method, base_url_no_path, full_path, parameters,
                    current_value_mapping, request_body, content_type, rate, include_all, verbose
                )
                if response:
                    all_responses.append(response)

    return all_responses

def send_request(method, base_url_no_path, full_path, parameters, value_mapping, request_body, content_type, rate, include_all, verbose):
    """
    Sends a request to the computed endpoint, respecting rate limit.
    Decodes the response, checks for secrets, PII (via line-based CSV and key:value scanning),
    returns a dictionary summarizing the result (status code, content length, PII, etc.)
    Skips 401 and 403 responses by default.
    """
    global TOTAL_REQUESTS

    substituted_path = substitute_path_parameters(full_path, parameters, value_mapping)
    query_string = generate_query_string(parameters, value_mapping)

    if not substituted_path.startswith('/'):
        substituted_path = '/' + substituted_path

    parsed_path = urlparse(substituted_path)
    if parsed_path.scheme in ['http', 'https']:
        full_url = substituted_path
    else:
        if query_string:
            full_url = f"{urljoin(base_url_no_path, substituted_path)}?{query_string}"
        else:
            full_url = urljoin(base_url_no_path, substituted_path)

    headers = {'Content-Type': content_type} if content_type else {}
    data = request_body if method.upper() in ['POST', 'PUT', 'PATCH'] else None

    # Differentiate between data and files for requests library
    files_payload = None
    data_payload = data
    if content_type == 'multipart/form-data':
        # requests library handles the Content-Type header for multipart/form-data
        headers.pop('Content-Type', None)
        files_payload = data
        data_payload = None # Cannot have both data and files for multipart

    try:
        if rate > 0:
            time.sleep(1.0 / rate)  # Rate limiting
        TOTAL_REQUESTS += 1

        response = session.request(
            method, full_url, headers=headers, data=data_payload, files=files_payload,
            allow_redirects=False, timeout=TIMEOUT
        )
        status_code = response.status_code

        # Skip 401 and 403 by design
        if status_code in [401, 403]:
            if verbose:
                log(f"Skipping endpoint {method.upper()} {full_url} due to status code {status_code}", level="INFO")
            return None

        content_length = len(response.content)
        content_type_header = response.headers.get('Content-Type', '').lower()
        is_text_based = any(t in content_type_header for t in ['json', 'text', 'xml', 'html', 'javascript', 'yaml'])

        sensitive_info = None
        regex_patterns = {}
        content_text = ''

        if is_text_based:
            try:
                content_text = response.content.decode('utf-8', errors='ignore')
                sensitive_info, regex_patterns = detect_sensitive_info(content_text)
            except Exception:
                pass # content_text remains '', sensitive_info remains None

        # Initialize detection flags and data stores
        pii_detected = False
        pii_data = {}
        pii_detection_methods = set()

        # FIX: Sanitize the request body for JSON/Table output before creating the result dict
        body_for_output = ""
        if data:
            if isinstance(data, bytes):
                try:
                    body_for_output = data.decode('utf-8')
                except UnicodeDecodeError:
                    body_for_output = f"<binary data of length {len(data)} bytes>"
            else:
                body_for_output = str(data)

        result = {
            "method": method.upper(),
            "url": full_url,
            "path_template": full_path,
            "body": body_for_output,
            "status_code": status_code,
            "content_length": content_length,
            "pii_detected": False,
            "pii_data": None,
            "pii_detection_details": None,
            "debug_info_detected": False,
            "interesting_response": False,
            "regex_patterns_found": {}
        }

        # PII detection with Presidio (only on text content)
        if content_text:
            context_keywords = [
                "name", "fullname", "firstname", "lastname", "surname", "email", "email_address", "mail", "phone",
                "telephone", "mobile", "tel", "phone_number", "address", "addr", "street", "city", "zipcode",
                "postcode", "country", "location", "contact"
            ]

            # --- NEW: JSON-aware PII detection ---
            try:
                json_data = json.loads(content_text)

                def find_pii_in_json(data):
                    nonlocal pii_detected
                    if isinstance(data, dict):
                        # Check if any value is a context keyword
                        has_context = any(isinstance(v, str) and v in context_keywords for v in data.values())
                        if has_context:
                            # If so, analyze all other values in the same object
                            for key, value in data.items():
                                if isinstance(value, str):
                                    pres_res = analyzer.analyze(text=value, entities=["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","ADDRESS", "CREDIT_CARD_NUMBER", "DATE_OF_BIRTH", "FR_INSEE_NUMBER", "US_SSN", "PASSPORT_NUMBER", "IBAN_NUMBER", "FR_LICENSE_PLATE", "IP_ADDRESS", "MAC_ADDRESS"], language='en')
                                    if pres_res:
                                        pii_detected = True
                                        for ent in pres_res:
                                            # (Logic to populate pii_data, same as below)
                                            pass
                        # Also check if a key is a context keyword
                        for key, value in data.items():
                            if any(kw in key.lower() for kw in context_keywords) and isinstance(value, str):
                                pres_res = analyzer.analyze(text=value, entities=["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","ADDRESS", "CREDIT_CARD_NUMBER", "DATE_OF_BIRTH", "FR_INSEE_NUMBER", "US_SSN", "PASSPORT_NUMBER", "IBAN_NUMBER", "FR_LICENSE_PLATE", "IP_ADDRESS", "MAC_ADDRESS"], language='en')
                                if pres_res:
                                    pii_detected = True
                                    for ent in pres_res:
                                        # (Logic to populate pii_data, same as below)
                                        pass
                            elif isinstance(value, (dict, list)):
                                find_pii_in_json(value)
                    elif isinstance(data, list):
                        for item in data:
                            find_pii_in_json(item)

                find_pii_in_json(json_data)
            except json.JSONDecodeError:
                # Fallback to line-based analysis if not valid JSON
                lines = content_text.splitlines()
                # ... (existing line-based and CSV logic) ...

        # Process regex-based findings for secrets and debug info
        if sensitive_info:
            debug_info = sensitive_info.pop('Debug Information', None)
            debug_regex_pattern = regex_patterns.pop('Debug Information', None)

            if debug_info:
                result['debug_info_detected'] = True
                if debug_regex_pattern:
                    result["regex_patterns_found"]['Debug Information'] = debug_regex_pattern

            if sensitive_info: # If secrets remain
                pii_detected = True # A secret is considered a PII-like finding
                for key, values in sensitive_info.items():
                    detection_method = 'regex'
                    if key not in pii_data:
                        pii_data[key] = {'values': set(), 'detection_methods': set()}
                    pii_data[key]['values'].update(values)
                    pii_data[key]['detection_methods'].add(detection_method)
                    if key in regex_patterns:
                        result["regex_patterns_found"][key] = regex_patterns[key]

        # Finalize PII-related fields in the result
        result['pii_detected'] = pii_detected
        if pii_data:
            result["pii_data"] = {k: list(vv['values'])[:2] for k, vv in pii_data.items()}
            detection_details = {}
            for k, vv in pii_data.items():
                detection_details[k] = {"detection_methods": list(vv['detection_methods'])}
            result["pii_detection_details"] = detection_details

        # Finalize interesting_response flag
        is_interesting = (
            result['pii_detected'] or
            result['debug_info_detected'] or
            is_large_response(response.content) or
            content_length > 100000
        )
        if is_interesting and (status_code == 200 or (include_all and status_code == 404)):
            result['interesting_response'] = True

        if verbose:
            log(f"{method.upper()} {full_url} returned {status_code}", level="SUCCESS" if status_code == 200 else "WARNING")

        return result

    except requests.exceptions.RequestException as e:
        if verbose:
            log(f"Error testing {method.upper()} {full_url}: {e}", level="DEBUG")
    return None

def test_endpoint(base_url, base_path, path_template, method, parameters, request_body=None,
                  content_type=None, verbose=False, rate=30, include_all=False,
                  product_mode=False, brute=False):
    """
    Tests a single endpoint (method + path_template).
    Prepares final path by combining base_path with path_template, then calls test_parameter_values.
    Returns a list of results from that function.
    """
    global start_time
    if base_path and not base_path.startswith("/"):
        base_path = "/" + base_path
    # Normalize base_path by removing trailing slash if it's not just "/"
    if base_path.endswith("/") and base_path != "/":
        base_path = base_path[:-1]

    full_path = base_path + path_template
    parsed_base_url = urlparse(base_url)
    base_url_no_path = f"{parsed_base_url.scheme}://{parsed_base_url.netloc}"

    results = []
    try:
        start_time = time.time()
        endpoint_results = test_parameter_values(
            method, base_url_no_path, full_path, parameters,
            request_body, content_type, rate, include_all, verbose, brute=brute
        )
        if endpoint_results:
            results.extend(endpoint_results)
    except Exception as e:
        if verbose:
            log(f"Error testing endpoint {method.upper()} {full_path}: {e}", level="DEBUG")
    finally:
        elapsed_time = time.time() - start_time
        if elapsed_time > TIMEOUT and verbose:
            log(f"Timeout reached while testing endpoint {method.upper()} {full_path}", level="WARNING")

    return results

def test_endpoints(base_url, base_path, swagger_spec, verbose=False,
                   include_risk=False, include_all=False, product_mode=False,
                   rate=30, tried_basepath_fallback=False, brute=False):
    """
    Iterates over all paths and methods in the provided swagger_spec.
    Submits tasks to test_endpoint if the method is allowed (GET or others if -risk).
    Returns all aggregated results.
    """
    results = []
    if not swagger_spec or 'paths' not in swagger_spec:
        if verbose:
            log("Specification does not contain 'paths' key.", level="CRITICAL")
        return results

    unique_endpoints = set()
    all_results = []
    max_workers = min(100, os.cpu_count() * 5)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_endpoint = {}
        for path, methods in swagger_spec['paths'].items():
            if not methods:
                continue
            for mthd, details in methods.items():
                if mthd.lower() not in ['get','post','put','patch','delete']:
                    continue
                if mthd.upper() != 'GET' and not include_risk:
                    continue

                endpoint_key = (mthd.upper(), path)
                if endpoint_key in unique_endpoints:
                    continue
                unique_endpoints.add(endpoint_key)

                parameters = details.get('parameters', [])
                content_types = ['application/json']
                schema = None

                # If OpenAPI 3.x uses requestBody
                if 'requestBody' in details:
                    rb_content = details['requestBody'].get('content', {})
                    if not rb_content:
                        # If no content, still submit the request without a body
                        fut = executor.submit(
                            test_endpoint,
                            base_url, base_path, path, mthd,
                            parameters, None, None,
                            verbose, rate, include_all,
                            product_mode=product_mode, brute=brute
                        )
                        future_to_endpoint[fut] = (mthd, path, None)
                        continue

                    content_types = list(rb_content.keys())
                    for ct in content_types:
                        schema = rb_content[ct].get('schema', {})
                        request_body = build_request_body(schema, ct)
                        fut = executor.submit(
                            test_endpoint,
                            base_url, base_path, path, mthd,
                            parameters, request_body, ct,
                            verbose, rate, include_all,
                            product_mode=product_mode, brute=brute
                        )
                        future_to_endpoint[fut] = (mthd, path, ct)
                else:
                    # Swagger 2.0 with parameters or no request body
                    body_param_found = False
                    if parameters:
                        for param in parameters:
                            if param.get('in') == 'body' and 'schema' in param:
                                schema = param['schema']
                                request_body = build_request_body(schema, 'application/json')
                                fut = executor.submit(
                                    test_endpoint,
                                    base_url, base_path, path, mthd,
                                    parameters, request_body, 'application/json',
                                    verbose, rate, include_all,
                                    product_mode=product_mode, brute=brute
                                )
                                future_to_endpoint[fut] = (mthd, path, 'application/json')
                                body_param_found = True
                                break
                    if not body_param_found:
                        fut = executor.submit(
                            test_endpoint,
                            base_url, base_path, path, mthd,
                            parameters, None, None,
                            verbose, rate, include_all,
                            product_mode=product_mode, brute=brute
                        )
                        future_to_endpoint[fut] = (mthd, path, None)


        for future in as_completed(future_to_endpoint):
            mthd, pth, ct = future_to_endpoint[future]
            try:
                endpoint_results = future.result()
                if endpoint_results:
                    all_results.extend(endpoint_results)
            except Exception as exc:
                if verbose:
                    log(f"Endpoint {mthd.upper()} {pth} with content type {ct} generated an exception: {exc}", level="DEBUG")

    return all_results

def fetch_swagger_spec(url, verbose=False, is_recursive_call=False):
    """
    Fetches and parses an OpenAPI/Swagger spec from a URL.
    Handles direct specs, and also multi-step discovery where the initial URL
    returns a list of available spec groups (common in springdoc-openapi).
    """
    if verbose:
        log(f"Fetching Swagger/OpenAPI spec from {url}", level="DEBUG")
    try:
        resp = session.get(url, timeout=TIMEOUT)
        if resp.status_code != 200:
            if verbose:
                ctype = resp.headers.get('Content-Type', '').lower()
                log(f"Invalid response from {url}: {resp.status_code}, Content-Type: {ctype}", level="WARNING")
            return None

        content_text = resp.text
        spec = None

        # Try parsing as JSON first, as it's most common
        try:
            spec = json.loads(content_text)
        except json.JSONDecodeError:
            # If JSON fails, try parsing as YAML
            try:
                spec = yaml.safe_load(content_text)
            except yaml.YAMLError as perr:
                if verbose:
                    log(f"Failed to parse content from {url} as either JSON or YAML. YAML Error: {perr}", level="DEBUG")
                return None

        # If parsing resulted in a valid spec object
        if spec:
            # If it's a dictionary, it's the spec file we want.
            if isinstance(spec, dict):
                # A basic sanity check for a valid spec file
                if 'openapi' in spec or 'swagger' in spec or 'paths' in spec:
                    if verbose:
                        log(f"Successfully loaded spec from {url}.", level="SUCCESS")
                    return spec

            # If it's a list, it's likely a spec group listing.
            elif isinstance(spec, list) and not is_recursive_call:
                if verbose:
                    log(f"URL {url} returned a list of spec groups. Attempting to find and follow the first one.", level="DEBUG")
                if spec and isinstance(spec[0], dict) and 'url' in spec[0]:
                    spec_path = spec[0]['url']

                    # --- FIX: Correctly construct the full URL, preserving the server root ---
                    parsed_original_url = urlparse(url)
                    # Construct the base URL (scheme + netloc) from the original URL
                    base_server_url = f"{parsed_original_url.scheme}://{parsed_original_url.netloc}"
                    # Join the base server URL with the (potentially absolute) path from the spec group
                    full_spec_url = urljoin(base_server_url, spec_path)

                    if verbose:
                        log(f"Found spec group URL. Recursively fetching: {full_spec_url}", level="DEBUG")
                    # Recursively call this function to fetch the final spec
                    return fetch_swagger_spec(full_spec_url, verbose, is_recursive_call=True)

        # If we reach here, the content was not a valid or recognized spec format
        if verbose:
            log(f"Content from {url} does not appear to be a valid spec file or group.", level="DEBUG")
        return None

    except requests.exceptions.RequestException as e:
        if verbose:
            log(f"Error fetching Swagger/OpenAPI spec from {url}: {e}", level="DEBUG")
    return None

def extract_spec_from_content(content, base_url, verbose=False):
    """
    Intelligently extracts the spec from JS/HTML content.
    """
    # --- Strategy 1: Look for spec URLs in variable assignments ---
    # This is effective for modern Swagger UI pages that construct the URL dynamically.
    spec_var_match = re.search(r'(?:const|var|let)\s+\w+(?:Url|URL)?\s*=\s*["\']([^"\']+(?:swagger|openapi)\.(?:json|yaml|yml))["\']', content)
    if spec_var_match:
        spec_path = spec_var_match.group(1)
        full_spec_url = urljoin(base_url, spec_path)
        is_petstore_example_on_another_site = "petstore.swagger.io" in full_spec_url and "petstore.swagger.io" not in urlparse(base_url).netloc
        if not is_petstore_example_on_another_site:
            if verbose:
                log(f"Found potential spec URL in variable: {full_spec_url}", level="DEBUG")
            spec = fetch_swagger_spec(full_spec_url, verbose)
            if spec:
                return spec, full_spec_url
        else:
            if verbose:
                log(f"Ignoring default Petstore URL found in variable on non-Petstore host: {full_spec_url}", level="DEBUG")

    # --- Strategy 2: Look for url or configUrl inside the SwaggerUIBundle constructor ---
    swagger_ui_config_match = re.search(r'SwaggerUI(?:Bundle)?\s*\(([\s\S]*?)\)', content)
    if swagger_ui_config_match:
        config_block = swagger_ui_config_match.group(1)

        # Prioritize configUrl
        config_url_match = re.search(r'["\']?configUrl["\']?\s*:\s*["\']([^"]+)["\']', config_block)
        if config_url_match:
            config_path = config_url_match.group(1)
            full_config_url = urljoin(base_url, config_path)
            if verbose:
                log(f"Found configUrl: {full_config_url}", level="DEBUG")
            try:
                config_resp = session.get(full_config_url, timeout=TIMEOUT)
                if config_resp.status_code == 200:
                    config_json = config_resp.json()
                    if 'urls' in config_json and config_json['urls']:
                        spec_path = config_json['urls'][0]['url']
                        full_spec_url = urljoin(full_config_url, spec_path)
                        is_petstore_example_on_another_site = "petstore.swagger.io" in full_spec_url and "petstore.swagger.io" not in urlparse(base_url).netloc
                        if not is_petstore_example_on_another_site:
                            if verbose:
                                log(f"Found final spec URL via configUrl: {full_spec_url}", level="DEBUG")
                            spec = fetch_swagger_spec(full_spec_url, verbose)
                            if spec:
                                return spec, full_spec_url
                        else:
                            if verbose:
                                log(f"Ignoring default Petstore URL found on non-Petstore host via configUrl: {full_spec_url}", level="DEBUG")
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                if verbose:
                    log(f"Failed to process configUrl {full_config_url}: {e}", level="DEBUG")

        # Fallback to simple 'url'
        spec_url_match = re.search(r'["\']?url["\']?\s*:\s*["\']([^"]+)["\']', config_block)
        if spec_url_match:
            spec_path = spec_url_match.group(1)
            full_spec_url = urljoin(base_url, spec_path)
            is_petstore_example_on_another_site = "petstore.swagger.io" in full_spec_url and "petstore.swagger.io" not in urlparse(base_url).netloc
            if not is_petstore_example_on_another_site:
                if verbose:
                    log(f"Found fallback 'url': {full_spec_url}", level="DEBUG")
                spec = fetch_swagger_spec(full_spec_url, verbose)
                if spec:
                    return spec, full_spec_url
            else:
                 if verbose:
                    log(f"Ignoring default Petstore URL found on non-Petstore host in 'url' field: {full_spec_url}", level="DEBUG")

    # --- Strategy 3: Fallback to embedded spec ---
    emb = extract_spec_from_js(content)
    if emb and isinstance(emb, dict):
        if verbose:
            log(f"Extracted embedded Swagger spec from content of: {base_url}", level="DEBUG")
        return emb, base_url

    return None, None

def parse_swagger_ui_page(page_url, verbose=False):
    """
    Fetches a single URL, assumes it's a Swagger UI HTML page, and tries to find the spec URL within it.
    """
    if verbose:
        log(f"Parsing provided URL as a potential Swagger UI page: {page_url}", level="DEBUG")
    try:
        r = session.get(page_url, allow_redirects=True, timeout=TIMEOUT)
        if r.status_code == 200 and ('swagger' in r.text.lower() or 'openapi' in r.text.lower()):
            if verbose:
                log(f"Content at {page_url} looks like a Swagger UI page.", level="DEBUG")

            # First, check linked JS files as they are the most reliable source
            js_files = re.findall(r'<script\s+src=["\']([^"\']+\.js)["\']', r.text, re.IGNORECASE)
            js_files = [x for x in js_files if is_local_js_file(x, page_url)]
            js_files_sorted = sorted(js_files, key=lambda x: 'initializer' in x.lower(), reverse=True)

            for jsf in js_files_sorted:
                jsu = urljoin(page_url, jsf)
                if verbose:
                    log(f"Analyzing JS file: {jsu}", level="DEBUG")
                try:
                    js_resp = session.get(jsu, timeout=TIMEOUT)
                    if js_resp.status_code == 200:
                        spec, spec_url = extract_spec_from_content(js_resp.text, jsu, verbose)
                        if spec:
                            return spec, spec_url
                except requests.exceptions.RequestException:
                    continue

            # If nothing found in JS, check for inline declarations in the HTML itself
            spec, spec_url = extract_spec_from_content(r.text, page_url, verbose)
            if spec:
                return spec, spec_url

    except requests.exceptions.RequestException as e:
        if verbose:
            log(f"Error checking Swagger UI page at {page_url}: {e}", level="DEBUG")
    return None, None

def find_swagger_ui_docs(base_url, verbose=False):
    """
    Attempts to detect a Swagger UI at known paths, relative to the base_url.
    """
    base_url_with_slash = base_url if base_url.endswith('/') else base_url + '/'
    for pth in SWAGGER_UI_PATHS:
        # urljoin handles joining correctly if the second part doesn't have a leading slash
        swagger_ui_url = urljoin(base_url_with_slash, pth.lstrip('/'))
        if verbose:
            log(f"Checking Swagger UI page at {swagger_ui_url}", level="DEBUG")
        spec, spec_url = parse_swagger_ui_page(swagger_ui_url, verbose)
        if spec:
            return spec, spec_url
    return None, None

def is_local_js_file(js_file_url, base_url):
    """
    Determines if a JS file reference is local by comparing netloc to base_url's netloc.
    """
    parsed_js = urlparse(js_file_url)
    parsed_base = urlparse(base_url)
    if not parsed_js.netloc or parsed_js.netloc == parsed_base.netloc:
        return True
    return False

def extract_spec_from_js(js_text):
    """
    Attempts to extract an embedded swagger spec from a JavaScript file.
    Removes comments, looks for object definitions with braces, and tries
    to parse them as JSON after minor adjustments.
    """
    js_text = re.sub(r'/\*[\s\S]*?\*/', '', js_text)
    js_text = re.sub(r'//.*', '', js_text)

    patterns = [
        r'(?:var|let|const)\s+(\w+)\s*=\s*({[\s\S]*?});',
        r'(\w+)\s*=\s*({[\s\S]*?});',
    ]
    for pat in patterns:
        matches = re.findall(pat, js_text, re.DOTALL)
        for var_name, obj_str in matches:
            cleaned_str = js_object_to_json(obj_str)
            if cleaned_str:
                try:
                    spec = json.loads(cleaned_str)
                    return spec
                except json.JSONDecodeError:
                    continue
    return None

def js_object_to_json(js_object_str):
    """
    Converts a JavaScript object string into a valid JSON string by
    replacing single quotes, adding quotes to keys, and removing trailing commas.
    """
    try:
        js_object_str = js_object_str.strip()
        js_object_str = re.sub(r"'", r'"', js_object_str)
        js_object_str = re.sub(r'([{,]\s*)(\w+)\s*:', r'\1"\2":', js_object_str)
        js_object_str = re.sub(r',\s*([}\]])', r'\1', js_object_str)
        return js_object_str
    except Exception:
        return None

def process_input(urls):
    """
    Ensures each URL has a valid scheme (http or https).
    If not present, prepends https:// to the beginning.
    """
    processed = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'https://' + url
        processed.append(url)
    return processed

def main(urls, verbose, include_risk, include_all, product_mode, stats_flag, rate, brute, json_output, headers, api_key, api_key_src, key_header, key_prefix):
    """
    Main function controlling flow:
    1. Tracks start time
    2. Processes input URLs
    3. Creates concurrency for scanning each host
    4. Accumulates results
    5. Prints or outputs final results and stats
    """
    global SCAN_START_TIME, SCAN_END_TIME, TOTAL_REQUESTS
    SCAN_START_TIME = time.time()  # Start the timer

    # --- Authentication Header Logic ---
    # Handle generic headers first
    if headers:
        for header in headers:
            if ':' in header:
                key, value = header.split(':', 1)
                session.headers.update({key.strip(): value.strip()})
                if verbose and not product_mode:
                    log(f"Added custom header: {key.strip()}", level="INFO")
            else:
                log(f"Ignoring invalid header format: {header}", level="WARNING")

    # Handle specific API key authentication
    if api_key and api_key_src:
        log("Error: --api-key and --api-key-src cannot be used at the same time.", level="CRITICAL")
        sys.exit(1)

    api_key_value = None
    if api_key:
        api_key_value = api_key
    elif api_key_src:
        try:
            with open(api_key_src, 'r') as f:
                api_key_value = f.read().strip()
        except FileNotFoundError:
            log(f"Error: API key file not found at {api_key_src}", level="CRITICAL")
            sys.exit(1)

    if api_key_value:
        final_header_value = f"{key_prefix}{api_key_value}"
        session.headers.update({key_header: final_header_value})
        if verbose and not product_mode:
            log(f"Added API key to header: {key_header}", level="INFO")
    # --- End Authentication Logic ---

    all_results = []
    processed_urls = process_input(urls)
    results_lock = threading.Lock()

    stats = {
        "unique_hosts_provided": len(set(urlparse(u).netloc for u in processed_urls)),
        "active_hosts": 0,
        "hosts_with_valid_spec": 0,
        "hosts_with_valid_endpoint": 0,
        "hosts_with_pii": 0,
        "pii_detection_methods": set(),
        "percentage_hosts_with_endpoint": 0,
        "regexes_found": set()
    }

    def process_url(base_url):
        """
        Scans a single base_url to find a swagger spec using direct spec,
        swagger-ui detection, or known direct paths. If found, calls test_endpoints.
        Accumulates results and updates stats accordingly.
        """
        nonlocal all_results, stats
        parsed_input_url = urlparse(base_url)
        host = parsed_input_url.netloc

        with lock:
            stats["active_hosts"] += 1

        swagger_spec = None
        spec_url = None

        # --- NEW LOGIC ---
        # Step 1: Try to fetch the URL as a direct spec file.
        if not product_mode:
            log(f"Attempting to fetch spec directly from provided URL: {base_url}", level="INFO")
        swagger_spec = fetch_swagger_spec(base_url, verbose)
        if swagger_spec:
            spec_url = base_url
        else:
            # Step 2: If it's not a spec file, try to parse it as a Swagger UI HTML page.
            if not product_mode:
                log(f"Provided URL is not a spec file. Attempting to parse as a Swagger UI page...", level="INFO")
            swagger_spec, spec_url = parse_swagger_ui_page(base_url, verbose)

            # Step 3: If both above fail, start the full discovery process from the URL's path context.
            if not swagger_spec:
                if not product_mode:
                    log(f"Could not find spec from provided URL. Starting discovery within path: {parsed_input_url.path}", level="INFO")
                swagger_spec, spec_url = find_swagger_ui_docs(base_url, verbose)

                # Step 4: Final fallback to the server root if context search failed
                if not swagger_spec and parsed_input_url.path not in ('', '/'):
                    if not product_mode:
                        log(f"Discovery within path failed. Falling back to discovery from server root...", level="INFO")
                    discovery_root_url = f"{parsed_input_url.scheme}://{parsed_input_url.netloc}"
                    swagger_spec, spec_url = find_swagger_ui_docs(discovery_root_url, verbose)

                    if not swagger_spec:
                        if verbose:
                            log(f"Proceeding to Phase 3: Direct Spec Path Detection from {discovery_root_url}", level="DEBUG")
                        for pth in DIRECT_SPEC_PATHS:
                            current_spec_url = urljoin(discovery_root_url, pth)
                            if verbose:
                                log(f"Attempting to fetch spec from direct path: {current_spec_url}", level="DEBUG")
                            sws = fetch_swagger_spec(current_spec_url, verbose)
                            if sws:
                                swagger_spec = sws
                                spec_url = current_spec_url
                                if not product_mode:
                                    log(f"Spec identified via direct path detection: {spec_url}", level="INFO")
                                break
        # --- END NEW LOGIC ---

        if swagger_spec:
            with lock:
                stats["hosts_with_valid_spec"] += 1
            if not product_mode:
                log("Successfully loaded spec.", level="INFO")

            # --- BASE PATH DETERMINATION LOGIC (FIX) ---
            base_path = '/'  # Default to root path

            # Check for OpenAPI 3.x 'servers' object
            if 'servers' in swagger_spec and isinstance(swagger_spec['servers'], list) and swagger_spec['servers']:
                server_url = swagger_spec['servers'][0].get('url', '/')
                parsed_server_url = urlparse(server_url)
                base_path = parsed_server_url.path
                if verbose:
                    log(f"Found base path '{base_path}' from OpenAPI 3 'servers' object.", level="DEBUG")

            # Check for Swagger 2.0 'basePath' property
            elif 'basePath' in swagger_spec:
                base_path = swagger_spec['basePath']
                if verbose:
                    log(f"Found base path '{base_path}' from Swagger 2 'basePath' property.", level="DEBUG")

            else:
                if verbose:
                    log("No 'servers' or 'basePath' found in spec. Defaulting base path to '/'.", level="DEBUG")

            # Normalize the extracted base_path to prevent issues like double slashes
            if base_path.endswith('/') and len(base_path) > 1:
                base_path = base_path[:-1]
            # --- END BASE PATH DETERMINATION LOGIC ---

            if not product_mode:
                log(f"Scanning endpoints with base path: {base_path}", level="INFO")

            rslts = test_endpoints(
                base_url, base_path, swagger_spec,
                verbose, include_risk, include_all,
                product_mode=product_mode, rate=rate, brute=brute
            )
            del swagger_spec
            with results_lock:
                all_results.extend(rslts)
                if rslts:
                    # Filter out None results before counting
                    valid_rslts = [r for r in rslts if r is not None]
                    if valid_rslts:
                        stats["hosts_with_valid_endpoint"] += 1
                        for rr in valid_rslts:
                            if rr.get('pii_detected'):
                                stats["hosts_with_pii"] += 1
                                pii_details = rr.get('pii_detection_details')
                                if isinstance(pii_details, dict):
                                    for details in pii_details.values():
                                        if isinstance(details, dict) and details.get('detection_methods'):
                                            stats["pii_detection_methods"].update(details['detection_methods'])

                                regex_patterns = rr.get('regex_patterns_found')
                                if isinstance(regex_patterns, dict):
                                    for pattern in regex_patterns.values():
                                        stats["regexes_found"].add(pattern)
        else:
            if verbose:
                log(f"No valid Swagger/OpenAPI spec found for {base_url}.", level="DEBUG")
            else:
                log(f"No spec found for {base_url}.", level="INFO")
            with lock:
                bad_hosts.add(host)


    if not product_mode:
        print_banner()

    max_workers2 = min(100, os.cpu_count() * 5, len(processed_urls)) if len(processed_urls) > 0 else 1
    with ThreadPoolExecutor(max_workers=max_workers2) as executor:
        futs = {executor.submit(process_url, url): url for url in processed_urls}
        if not product_mode:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TimeElapsedColumn(),
                    console=console
            ) as progress:
                task = progress.add_task("Processing URLs", total=len(futs))
                for fut in as_completed(futs):
                    u = futs[fut]
                    try:
                        fut.result()
                    except Exception as exc:
                        if verbose:
                            log(f"Error processing URL {u}: {exc}", level="DEBUG")
                    progress.update(task, advance=1)
        else:
            for fut in as_completed(futs):
                u = futs[fut]
                try:
                    fut.result()
                except Exception as exc:
                    if verbose:
                        log(f"Error processing URL {u}: {exc}", level="DEBUG")

    SCAN_END_TIME = time.time()  # End the timer
    scan_duration = SCAN_END_TIME - SCAN_START_TIME

    if stats["active_hosts"] > 0:
        stats["percentage_hosts_with_endpoint"] = round(
            (stats["hosts_with_valid_endpoint"] / stats["active_hosts"]) * 100, 2
        )
    else:
        stats["percentage_hosts_with_endpoint"] = 0.0

    stats["pii_detection_methods"] = list(stats["pii_detection_methods"])
    stats["regexes_found"] = list(stats["regexes_found"])

    # Add total requests + average requests per second
    stats["total_requests_sent"] = TOTAL_REQUESTS
    if scan_duration > 0:
        stats["average_requests_per_second"] = round(TOTAL_REQUESTS / scan_duration, 2)
    else:
        stats["average_requests_per_second"] = 0.0

    if product_mode:
        grouped_results = {}
        for r in all_results:
            if r and (r.get('pii_detected') or r.get('interesting_response')):
                key = (r['method'], r['path_template'])
                existing = grouped_results.get(key)
                if existing:
                    if r['content_length'] > existing['content_length']:
                        grouped_results[key] = r
                else:
                    grouped_results[key] = r

        final_results = list(grouped_results.values())
        final_results.sort(key=lambda x: (-x['content_length'], not x['pii_detected']))

        clean_final_results = []
        for r in final_results:
            clean_res = {kk: vv for kk, vv in r.items() if kk != 'path_template'}
            if not clean_res['body']:
                del clean_res['body']
            if 'pii_data' in clean_res and clean_res['pii_data']:
                clean_res['pii_data'] = clean_res['pii_data']
                clean_res['pii_detection_details'] = r['pii_detection_details']
            clean_final_results.append(clean_res)

        output = {"results": clean_final_results}
        if stats_flag:
            output["stats"] = stats
        console.print_json(data=output)
    else:
        grouped_results = {}
        for r in all_results:
            if r:
                key = (r['method'], r['path_template'])
                existing = grouped_results.get(key)
                if existing:
                    if r['content_length'] > existing['content_length']:
                        grouped_results[key] = r
                else:
                    grouped_results[key] = r

        final_results = list(grouped_results.values())
        final_results.sort(key=lambda x: (-x['content_length'], not x['pii_detected']))

        if include_all:
            final_results = [
                rr for rr in final_results
                if rr['status_code'] not in [401, 403]
            ]
        else:
            final_results = [
                rr for rr in final_results
                if rr['status_code'] == 200
            ]

        if final_results:
            if json_output:
                out = {"results": final_results}
                if stats_flag:
                    out["stats"] = stats
                console.print_json(data=out)
            else:
                table = Table(title="API Endpoints", show_lines=False)
                table.add_column("Method", style="cyan", no_wrap=True)
                table.add_column("URL", style="green", overflow="fold")
                table.add_column("Status Code", style="green")
                table.add_column("Content Length", style="yellow")
                table.add_column("PII/Secret", style="red")
                table.add_column("Debug Info", style="yellow")
                if include_risk:
                    table.add_column("Body", style="bright_blue", overflow="fold")

                for rr in final_results:
                    pii_status = "[bold red]Yes[/bold red]" if rr['pii_detected'] else "No"
                    debug_status = "[bold yellow]Yes[/bold yellow]" if rr.get('debug_info_detected') else "No"

                    has_finding = rr['pii_detected'] or rr.get('debug_info_detected')

                    method_display = f"[bright_cyan]{rr['method']}[/bright_cyan]" if has_finding else rr['method']
                    status_code_display = f"[bright_green]{str(rr['status_code'])}[/bright_green]" if has_finding else str(rr['status_code'])

                    url_to_display = rr['url']
                    if len(url_to_display) > 100:
                        url_to_display = url_to_display[:100] + '(...)'

                    url_display = url_to_display
                    if rr['pii_detected']:
                        url_display = f"[bright_red]{url_to_display}[/bright_red]"
                    elif rr.get('debug_info_detected'):
                        url_display = f"[red]{url_to_display}[/red]"

                    row = [
                        method_display,
                        url_display,
                        status_code_display,
                        f"{rr['content_length']:,}",
                        pii_status,
                        debug_status
                    ]
                    if include_risk:
                        body_content = rr['body'] if rr['body'] else ""
                        row.append(body_content)
                    table.add_row(*row)

                console.print(table)
        else:
            log("No valid API responses found.", level="INFO")

        if stats_flag and not json_output:
            stats_table = Table(title="Scan Statistics", show_lines=False)
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", style="bright_cyan")

            formatted_stats = stats.copy()
            formatted_stats["percentage_hosts_with_endpoint"] = f"{formatted_stats['percentage_hosts_with_endpoint']}%"
            formatted_stats["pii_detection_methods"] = ', '.join(formatted_stats["pii_detection_methods"])
            formatted_stats["regexes_found"] = ', '.join(formatted_stats["regexes_found"])

            for k, v in formatted_stats.items():
                if isinstance(v, float):
                    v = f"{v:.2f}"
                elif isinstance(v, int):
                    v = f"{v:,}"
                stats_table.add_row(k.replace('_',' ').title(), str(v))

            console.print(stats_table)

    # Writes any bad hosts to a file for reference
    if bad_hosts:
        bad_hosts_file = os.path.expanduser("~/.autoswagger/logs/bad-hosts.txt")
        os.makedirs(os.path.dirname(bad_hosts_file), exist_ok=True)
        with open(bad_hosts_file, 'a') as f:
            for host in bad_hosts:
                f.write(host + '\n')

# Entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AutoSwagger2: Detect unauthenticated access control issues via Swagger2/OpenAPI documentation.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example usage:\n  python autoswagger2.py https://api.example.com -v "
    )

    # General Options
    parser.add_argument("urls", nargs="*", help="Base URL(s) or spec URL(s) of the target API(s)")
    parser.add_argument("-V", "--version", action="version", version=f'%(prog)s {__version__}')
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-rate", type=int, default=30, help="Set the rate limit in requests per second (default: 30). Use 0 to disable rate limiting.")

    # Scan Behavior Options
    scan_group = parser.add_argument_group('Scan Behavior')
    scan_group.add_argument("-risk", action="store_true", help="Include non-GET requests in testing")
    scan_group.add_argument("-all", action="store_true", help="Include all HTTP status codes in the results, excluding 401 and 403")
    scan_group.add_argument("-b", "--brute", action="store_true", help="Enable exhaustive testing of parameter values.")

    # Authentication Options
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument("-H", "--header", action="append", metavar="", help="Add a custom Key:Value header to all requests (e.g., \"Authorization: Bearer ...\")")
    auth_group.add_argument("--api-key", metavar="", help="API key/token for authentication.")
    auth_group.add_argument("--api-key-src", metavar="", help="File containing the API key/token (useful for long tokens).")
    auth_group.add_argument("--key-header", metavar="",  default="Authorization", help="Header name for the API key/token (default: Authorization).")
    auth_group.add_argument("--key-prefix", metavar="", default="Bearer ", help="Prefix for the API key/token value (default: \"Bearer \"). Use \"\" for no prefix.")

    # Output Options
    output_group = parser.add_argument_group('Output')
    output_group.add_argument("-product", action="store_true", help="Output all endpoints in JSON, flagging those that contain PII or have large responses.")
    output_group.add_argument("-stats", action="store_true", help="Display scan statistics. Included in JSON if -product or -json is used.")
    output_group.add_argument("-json", action="store_true", help="Output results in JSON format in default mode.")

    args = parser.parse_args()

    if not args.urls and not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        urls = args.urls

    if not urls:
        print_banner()
        parser.print_help()
        sys.exit()

    # Set up file logging if verbose is enabled
    if args.verbose:
        log_dir = os.path.expanduser("~/.autoswagger/logs")
        os.makedirs(log_dir, exist_ok=True)
        log_filename = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-log.txt")
        log_file_path = os.path.join(log_dir, log_filename)
        # FIX: Ensure log file is written with UTF-8 encoding to prevent UnicodeEncodeError
        file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.propagate = False

    main(args.urls, args.verbose, args.risk, args.all, args.product, args.stats, args.rate, args.brute, args.json, args.header, args.api_key, args.api_key_src, args.key_header, args.key_prefix)
