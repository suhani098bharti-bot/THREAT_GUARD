"""Input validation helpers for ThreatGuard."""

import ipaddress
import re
from typing import Tuple


def is_valid_ipv4_or_ipv6(ip_str: str) -> bool:
    """Validate whether input is a properly formatted IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_valid_port(port_val: any) -> bool:
    """Validate whether port is an integer in valid range 1-65535."""
    try:
        p = int(port_val)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


def sanitize_text(text: str, max_length: int = 1000) -> str:
    """Strip dangerous characters and trim length for safe display."""
    if not text:
        return ""
    # Strip null bytes and normalize whitespace
    cleaned = text.replace("\x00", "").strip()
    return cleaned[:max_length]
