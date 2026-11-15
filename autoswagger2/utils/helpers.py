# autoswagger2/utils/helpers.py
# Contains small utility functions.

import time
import logging
from collections.abc import Mapping
from urllib.parse import urlparse
from rich.console import Console

console = Console(stderr=True)
logger = logging.getLogger("autoswagger")

SAFE_CROSS_ORIGIN_HEADERS = {
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "connection",
}


def is_quiet_output(args):
    """Returns True when stdout must stay clean for machine-readable JSON output."""
    return bool(getattr(args, "product", False) or getattr(args, "json", False))


def join_base_and_path(base_path, path):
    """Joins an API base path and an endpoint path without producing leading '//'."""
    clean_base = "/" + base_path.strip("/") if (base_path and base_path.strip("/")) else ""
    clean_path = "/" + (path or "").lstrip("/")
    return f"{clean_base}{clean_path}"


def build_full_url(api_base_url, path_or_url):
    """Constructs a full URL safely from base URL and path or absolute URL."""
    if path_or_url and path_or_url.startswith(("http://", "https://")):
        return path_or_url
    norm_path = "/" + (path_or_url or "").lstrip("/")
    norm_base = (api_base_url or "").rstrip("/")
    return f"{norm_base}{norm_path}" if norm_base else norm_path


def _effective_port(parsed):
    if parsed.port is not None:
        return parsed.port
    scheme = (parsed.scheme or "").lower()
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def is_same_origin_host(reference_url, candidate_url):
    """
    Checks whether candidate_url stays on the same host and port as reference_url
    (allowing standard http->https upgrade on ports 80->443). Relative URLs return True.
    """
    parsed_cand = urlparse(candidate_url or "")
    if not parsed_cand.scheme and not parsed_cand.netloc:
        return True
    if parsed_cand.scheme.lower() not in ("http", "https"):
        return False

    parsed_ref = urlparse(reference_url or "")
    ref_host = (parsed_ref.hostname or "").lower()
    cand_host = (parsed_cand.hostname or "").lower()
    if not ref_host or not cand_host or ref_host != cand_host:
        return False

    try:
        ref_port = _effective_port(parsed_ref)
        cand_port = _effective_port(parsed_cand)
    except ValueError:
        return False

    if ref_port == cand_port:
        return True
    if (
        (parsed_ref.scheme or "").lower() == "http"
        and parsed_cand.scheme.lower() == "https"
        and ref_port == 80
        and cand_port == 443
    ):
        return True
    return False


def build_cross_origin_safe_headers(session, extra_headers=None):
    """
    Returns a per-request headers dict that strips sensitive session headers
    (e.g. Authorization, Cookie, custom auth headers) by setting them to None.
    """
    headers = dict(extra_headers) if extra_headers else {}
    explicit_keys = {k.lower() for k in headers}
    session_headers = getattr(session, "headers", None)
    if isinstance(session_headers, Mapping):
        for key in list(session_headers.keys()):
            key_lower = key.lower()
            if key_lower not in SAFE_CROSS_ORIGIN_HEADERS and key_lower not in explicit_keys:
                headers[key] = None
    return headers

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

    if logger.hasHandlers():
        if level == "DEBUG":
            logger.debug(message)
        elif level in ["INFO", "WARNING", "CRITICAL", "SUCCESS"]:
            logger.info(message)

def print_banner():
    """
    Prints the ASCII banner for Autoswagger2 with jservlet.com link in yellow.
    Called if not in product mode, to show the standard header.
    """
    banner = fr"""[white]
    ___         __      _____                                    [bold bright_red] ___ [/bold bright_red]
   /   | __  __/ / ____/ ___/__     __ _____ _____ ____ ___  ____[bold bright_red]|__ \ [/bold bright_red]
  / /| |/ / / / __/ __ \\__ \ | /| / / __ `/ __ `/ __ `/ _ \/ ___/[bold bright_red]_/ / [/bold bright_red]
 / ___ / /_/ / /_/ /_/ /__/ / |/ |/ / /_/ / /_/ / /_/ /  __/ /  [bold bright_red]/ __/ [/bold bright_red]
/_/  |_\__,_/\__/\____/____/|__/|__/\__,_/\__, /\__, /\___/_/  [bold bright_red]/____/ [/bold bright_red]
                                         /____//____/    [/white]
                              [yellow]https://jservlet.com[/yellow]
                          Find unauthenticated endpoints
    """
    console.print(banner)
