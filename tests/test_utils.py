"""Tests for the utility functions in the network reputation check tool."""

from network_reputation_check.utils import is_cidr, is_domain, is_ip


def test_is_ip() -> None:
    """Test the is_ip function.

    Ensures that valid IPv4 and IPv6 addresses return True,
    and invalid IP addresses or domains return False.
    """
    assert is_ip("8.8.8.8")
    assert is_ip("2001:4860:4860::8888")
    assert not is_ip("example.com")


def test_is_cidr() -> None:
    """Test the is_cidr function.

    Ensures that valid CIDR blocks return True,
    and invalid CIDR blocks or domains return False.
    """
    assert is_cidr("192.168.0.0/16")
    assert not is_cidr("example.com")


def test_is_domain() -> None:
    """Test the is_domain function.

    Ensures that valid domains return True,
    and IP addresses or CIDR blocks return False.
    """
    assert is_domain("example.com")
    assert is_domain("sub.example.co.uk")
    assert not is_domain("8.8.8.8")
    assert not is_domain("192.168.0.0/16")
