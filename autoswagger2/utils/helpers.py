# autoswagger2/utils/helpers.py
# Contains small utility functions.

import time
import logging
from rich.console import Console

console = Console()
logger = logging.getLogger("autoswagger")

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
