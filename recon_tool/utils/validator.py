"""
Input validation utilities.
"""

import re
import socket
import ipaddress
from typing import Union
from urllib.parse import urlparse


def validate_input(target: str) -> bool:
    """Validate if input is a valid domain or IP address.
    
    Args:
        target: Input to validate
        
    Returns:
        True if valid, False otherwise
    """
    target = sanitize_target(target)
    
    # Check if it's a valid IP address
    if is_valid_ip(target):
        return True
    
    # Check if it's a valid domain
    if is_valid_domain(target):
        return True
    
    return False


def sanitize_target(target: str) -> str:
    """Clean and sanitize target input.
    
    Args:
        target: Target domain or IP
        
    Returns:
        Sanitized target string
    """
    if not target:
        return ""
    
    # Remove protocol if present
    target = target.strip().lower()
    if '://' in target:
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    
    # Remove trailing slashes and paths
    target = target.split('/')[0]
    
    return target


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IP address.
    
    Args:
        ip_str: String to check
        
    Returns:
        True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Check if string is a valid domain name.
    
    Args:
        domain: Domain to validate
        
    Returns:
        True if valid domain, False otherwise
    """
    # Basic domain pattern validation
    if not domain or len(domain) > 255:
        return False
    
    # Check for invalid characters
    if re.search(r'[^a-zA-Z0-9.-]', domain):
        return False
    
    # Check if it has at least one dot and correct TLD
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    # Check each part
    for part in parts:
        if not part or len(part) > 63:
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
    
    return True


def is_reachable(target: str, port: int = 80, timeout: float = 2.0) -> bool:
    """Check if target is reachable.
    
    Args:
        target: Domain or IP
        port: Port to check
        timeout: Connection timeout
        
    Returns:
        True if reachable
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except Exception:
        return False