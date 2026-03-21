# autoswagger2/__main__.py
# Handles command-line arguments and starts the scan.

import argparse
import sys
import os
import logging
from datetime import datetime
import requests
import urllib3

from .core.scanner import Scanner
from .utils.helpers import print_banner
from .utils.config import __version__

# The session object is created here once and passed down.
session = requests.Session()

def run():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(
        prog='autoswagger2',
        description="AutoSwagger2: Detect unauthenticated access control issues via Swagger2/OpenAPI documentation.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example usage:\n  python -m autoswagger2 https://api.example.com -v "
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
    scan_group.add_argument("--test-bfla", action="store_true", help="Test for Broken Function Level Authorization (BFLA). Requires an auth header.")
    scan_group.add_argument("--test-bopla", action="store_true", help="Test for Broken Object Property Level Authorization (BOPLA).")
    scan_group.add_argument("--test-urc", action="store_true", help="Test for Unrestricted Resource Consumption (DoS).")


    # Authentication Options
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument("-H", "--header", action="append", metavar="", help="Add a custom Key:Value header to all requests (e.g., \"Authorization: Bearer ...\")")
    auth_group.add_argument("--api-key", metavar="", help="API key/token for authentication.")
    auth_group.add_argument("--api-key-src", metavar="", help="File containing the API key/token (useful for long tokens).")
    auth_group.add_argument("--key-header", metavar="",  default="Authorization", help="Header name for the API key/token (default: Authorization).")
    auth_group.add_argument("--key-prefix", metavar="", default="Bearer ", help="Prefix for the API key/token value (default: \"Bearer \"). Use \"\" for no prefix.")

    # BOLA Testing Options
    bola_group = parser.add_argument_group('BOLA Testing')
    bola_group.add_argument("--bola", action="store_true", help="Enable BOLA testing mode.")
    bola_group.add_argument("--bola-id", metavar='"param=id"', help="Parameter name and your ID for BOLA baseline (e.g., \"userId=123\").")

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
        file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(message)s")
        file_handler.setFormatter(formatter)

        logger = logging.getLogger("autoswagger")
        logger.addHandler(file_handler)
        logger.propagate = False

    # Configure the global session object
    session.headers.update({'User-Agent': f'AutoSwagger2/{__version__}'})
    session.verify = False

    # Pass the configured session to the Scanner
    scanner = Scanner(urls, args, session)
    scanner.run()

if __name__ == '__main__':
    run()
