"""Utility functions for validating IPs, CIDR blocks, and domains."""

import ipaddress
import re

import validators

# Match any valid TLD-style suffix (e.g. .local, .internal, .clear)
INTERNAL_DOMAIN_REGEX: re.Pattern[str] = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z0-9]{2,}$",
)


def is_ip(value: str) -> bool:
    """Check if the given value is a valid IPv4 or IPv6 address.

    Args:
    ----
        value: The string to check.

    Returns:
    -------
        True if the value is a valid IP address, False otherwise.

    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    else:
        return True


def is_cidr(value: str) -> bool:
    """Check if the given value is a valid CIDR block.

    Args:
    ----
        value: The string to check.

    Returns:
    -------
        True if the value is a valid CIDR block, False otherwise.

    """
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    else:
        return True


def is_domain(value: str, *, allow_internal: bool = True) -> bool:
    """Check if the given value is a valid domain.

    This function supports both public domains (validated via the `validators` library)
    and optional internal domains (validated via a regex).

    Args:
    ----
        value: The string to check.
        allow_internal: Whether to allow internal domains (e.g., `.local`).

    Returns:
    -------
        True if the value is a valid domain, False otherwise.

    """
    if is_ip(value) or is_cidr(value):
        return False

    if validators.domain(value):
        return True

    return bool(allow_internal and INTERNAL_DOMAIN_REGEX.fullmatch(value))
