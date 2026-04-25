"""Tests for indicator scanning and SARIF generation."""

import json
from pathlib import Path

from network_reputation_check.sarif import build_sarif_run, classify_level
from network_reputation_check.scanner import (
    IndicatorCandidate,
    IndicatorHit,
    discover_indicators,
    sanitize_indicator_value,
)


def test_discover_indicators_filters_non_public(tmp_path: Path) -> None:
    """Ensure scanner extracts public indicators and skips local-only values."""
    sample = tmp_path / "sample.txt"
    sample.write_text(
        "connect to 8.8.8.8 and example.com\n"
        "internal 10.0.0.1 localhost app.local app.internal 192.168.0.0/16\n"
        "range 8.8.8.0/24 and domain bad.example.org\n",
        encoding="utf-8",
    )

    found = discover_indicators(tmp_path)
    values = {(item.value, item.kind) for item in found}

    assert ("8.8.8.8", "ip") in values
    assert ("8.8.8.0/24", "cidr") in values
    assert ("bad.example.org", "domain") in values
    assert ("10.0.0.1", "ip") not in values
    assert ("example.com", "domain") not in values
    assert ("app.local", "domain") not in values
    assert ("app.internal", "domain") not in values


def test_sarif_levels_and_payload() -> None:
    """Ensure SARIF payload emits the expected severity levels."""
    indicator = IndicatorCandidate(
        value="evil.example",
        kind="domain",
        locations=(IndicatorHit(value="evil.example", kind="domain", file_path="a.txt", line=3),),
    )

    payload = build_sarif_run(
        "virustotal",
        [
            (indicator, {"stats": {"malicious": 2, "suspicious": 0}}),
            (indicator, {"stats": {"malicious": 0, "suspicious": 1}}),
            (indicator, {"stats": {"malicious": 0, "suspicious": 0, "harmless": 42}}),
        ],
    )

    result_levels = [item["level"] for item in payload["runs"][0]["results"]]
    assert "error" in result_levels
    assert "warning" in result_levels
    assert "note" in result_levels

    assert classify_level({"stats": {"malicious": 1}}) == "error"
    assert classify_level({"stats": {"suspicious": 1}}) == "warning"
    assert classify_level({"stats": {"harmless": 1}}) == "note"

    json.dumps(payload)


def test_sanitize_indicator_value_strips_wrappers_and_crlf() -> None:
    """Ensure extracted indicators are normalized safely."""
    assert sanitize_indicator_value("('8.8.8.8')\r\n") == "8.8.8.8"


def test_review_examples_include_good_and_bad_indicators(tmp_path: Path) -> None:
    """Include explicit review examples for benign/suspicious-looking indicators."""
    good_ip = "1.1.1.1"
    bad_ip_for_review = "45.9.148.108"
    good_domain = "cloudflare.com"
    bad_domain_for_review = "malicious-example.net"
    good_cidr = "8.8.4.0/24"
    bad_cidr_for_review = "185.220.100.0/24"

    sample = tmp_path / "review_examples.txt"
    sample.write_text(
        (
            f"good_ip={good_ip}\n"
            f"bad_ip={bad_ip_for_review}\n"
            f"good_domain={good_domain}\n"
            f"bad_domain={bad_domain_for_review}\n"
            f"good_cidr={good_cidr}\n"
            f"bad_cidr={bad_cidr_for_review}\n"
        ),
        encoding="utf-8",
    )

    found = discover_indicators(tmp_path)
    values = {(item.value, item.kind) for item in found}

    assert (good_ip, "ip") in values
    assert (bad_ip_for_review, "ip") in values
    assert (good_domain, "domain") in values
    assert (bad_domain_for_review, "domain") in values
    assert (good_cidr, "cidr") in values
    assert (bad_cidr_for_review, "cidr") in values
