"""Tests for the constants module of the network reputation check tool."""

from network_reputation_check.constants import DEFAULT_SOURCES, Source


def test_sources() -> None:
    """Test that the default sources match the expected set of supported sources.

    Ensures that DEFAULT_SOURCES contains the correct values for supported
    reputation check sources.
    """
    assert set(DEFAULT_SOURCES) == {"virustotal", "urlscan"}


def test_source_enum() -> None:
    """Test that the Source enum contains the correct values.

    Ensures that the Source enum values match the expected strings for
    supported reputation check sources.
    """
    assert Source.VIRUSTOTAL.value == "virustotal"
    assert Source.URLSCAN.value == "urlscan"
    # Removed: assert Source.CISCO_TALOS.value == "cisco_talos"
