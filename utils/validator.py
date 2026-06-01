"""
Input validation utilities – hardened against injection and malformed input.
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse


# ── public API ────────────────────────────────────────────────────
def validate_input(target: str) -> bool:
    """Return True if *target* is a syntactically valid domain or IP."""
    if not target or len(target) > 255:
        return False
    t = sanitize_target(target)
    return is_valid_ip(t) or is_valid_domain(t)


def sanitize_target(target: str) -> str:
    """
    Strip protocol, path, query-string and port from an arbitrary user string.
    Returns a lowercase hostname/IP (bare – no brackets, no port).
    """
    if not target:
        return ""
    target = target.strip()

    # Strip protocol via urlparse (handles IPv6 brackets correctly)
    if "://" in target:
        parsed = urlparse(target)
        # parsed.hostname already strips port and brackets
        target = parsed.hostname or parsed.netloc or parsed.path

    # At this point we may have:
    #   host.example.com
    #   host.example.com:8080
    #   [::1]:443
    #   ::1

    # Strip path/query/fragment (only up to first '/')
    target = target.split("/")[0].split("?")[0].split("#")[0]

    # Strip brackets and trailing port for bracketed IPv6 like [::1]:443
    if target.startswith("["):
        target = target.lstrip("[").split("]")[0]
    elif ":" in target and target.count(":") == 1:
        # single colon → hostname:port (not IPv6)
        target = target.rsplit(":", 1)[0]
    # else: bare IPv6 (multiple colons) or plain hostname – leave as-is

    return target.lower()


def is_valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr.strip("[]"))
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """
    Validate domain name:
      - Only alphanumeric, hyphens and dots
      - Each label <= 63 chars, no leading/trailing hyphen
      - At least two labels (needs a TLD)
    """
    if not domain or len(domain) > 253:
        return False
    if re.search(r"[^a-zA-Z0-9.\-]", domain):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.match(r"^[a-zA-Z0-9\-]+$", label):
            return False
    return True


def is_reachable(target: str, port: int = 80, timeout: float = 2.0) -> bool:
    """TCP connectivity check."""
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except Exception:
        return False
