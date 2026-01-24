"""
Logging utility for consistent logging across modules.
"""

import logging
import sys
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)


def setup_logger(name: str, verbose: bool = False) -> logging.Logger:
    """Setup a logger with colored output.
    
    Args:
        name (str): Logger name
        verbose (bool): Enable debug logging
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Set level
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    # Create console handler with colored output
    handler = logging.StreamHandler(sys.stdout)
    
    # Create formatter
    class ColoredFormatter(logging.Formatter):
        """Custom formatter with colored output."""
        
        COLORS = {
            'DEBUG': Fore.CYAN,
            'INFO': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.RED + Style.BRIGHT
        }
        
        def format(self, record):
            # Add color based on level
            level_color = self.COLORS.get(record.levelname, '')
            record.levelname = f"{level_color}{record.levelname}{Style.RESET_ALL}"
            record.msg = f"{level_color}{record.msg}{Style.RESET_ALL}"
            return super().format(record)
    
    formatter = ColoredFormatter(
        '[%(asctime)s] %(levelname)s - %(name)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def log(message: str, level: str = "INFO"):
    """Simple logging function.
    
    Args:
        message (str): Message to log
        level (str): Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    logger = logging.getLogger(__name__)
    if level == "DEBUG":
        logger.debug(message)
    elif level == "INFO":
        logger.info(message)
    elif level == "WARNING":
        logger.warning(message)
    elif level == "ERROR":
        logger.error(message)
    elif level == "CRITICAL":
        logger.critical(message)
    else:
        logger.info(message)