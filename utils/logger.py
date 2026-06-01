"""
Logging utility – coloured, consistent output across all modules.
"""

import logging
import sys

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    _COLOUR = True
except ImportError:
    _COLOUR = False


def setup_logger(name: str, verbose: bool = False) -> logging.Logger:
    """Return a configured, coloured logger."""
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler(sys.stdout)

    if _COLOUR:
        class _CF(logging.Formatter):
            _MAP = {
                "DEBUG":    Fore.CYAN,
                "INFO":     Fore.GREEN,
                "WARNING":  Fore.YELLOW,
                "ERROR":    Fore.RED,
                "CRITICAL": Fore.RED + Style.BRIGHT,
            }
            def format(self, record):
                c = self._MAP.get(record.levelname, "")
                record.levelname = f"{c}{record.levelname:<8}{Style.RESET_ALL}"
                record.msg       = f"{c}{record.msg}{Style.RESET_ALL}"
                return super().format(record)

        fmt = _CF("[%(asctime)s] %(levelname)s %(message)s", datefmt="%H:%M:%S")
    else:
        fmt = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s",
                                datefmt="%H:%M:%S")

    handler.setFormatter(fmt)
    logger.addHandler(handler)
    return logger
