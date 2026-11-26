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
        "range 8.8.8.0/24 and domain reputation-demo.com\n",
        encoding="utf-8",
    )

    found = discover_indicators(tmp_path)
    values = {(item.value, item.kind) for item in found}

    assert ("8.8.8.8", "ip") in values
    assert ("8.8.8.0/24", "cidr") in values
    assert ("reputation-demo.com", "domain") in values
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
    bad_domain_for_review = "reputation-review.net"
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


def test_discovery_skips_symlinks_and_generated_outputs(tmp_path: Path) -> None:
    """Keep external files and reports out of provider requests."""
    root = tmp_path / "repo"
    root.mkdir()
    external = tmp_path / "outside.txt"
    external.write_text("8.8.8.8", encoding="utf-8")
    (root / "link.txt").symlink_to(external)
    (root / "linked-dir").symlink_to(tmp_path, target_is_directory=True)
    report = root / "results.json"
    report.write_text('{"target": "1.1.1.1"}', encoding="utf-8")
    assert discover_indicators(root, excluded_paths={report}) == []


def test_discovery_deduplicates_and_preserves_cidrs(tmp_path: Path) -> None:
    """Avoid duplicate requests for domains, equivalent IPv6 addresses and CIDR bases."""
    (tmp_path / "a.txt").write_text(
        "CLOUDFLARE.COM cloudflare.com 2606:4700:4700::1111 2606:4700:4700:0:0:0:0:1111 8.8.4.0/24",
        encoding="utf-8",
    )
    found = {item.value: item for item in discover_indicators(tmp_path)}
    assert set(found) == {"cloudflare.com", "2606:4700:4700::1111", "8.8.4.0/24"}
    assert len(found["cloudflare.com"].locations) == 1


def test_reserved_example_subdomains_are_not_sent(tmp_path: Path) -> None:
    """Respect reserved example domains including their subdomains."""
    (tmp_path / "a.txt").write_text("bad.example.org child.example.com app.local 10.0.0.1", encoding="utf-8")
    assert discover_indicators(tmp_path) == []


def test_sarif_uri_encodes_filename_characters() -> None:
    """Keep URI fragments and percent escapes from changing file locations."""
    indicator = IndicatorCandidate("8.8.8.8", "ip", (IndicatorHit("8.8.8.8", "ip", "src/a #%.txt", 1),))
    report = build_sarif_run("virustotal", [(indicator, {"error": "Rate limited"})])
    run = report["runs"][0]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/a%20%23%25.txt"
    assert run["invocations"][0]["executionSuccessful"] is False


def test_nested_scan_locations_are_relative_to_workspace(tmp_path: Path, monkeypatch: object) -> None:
    """Point annotations and SARIF at the checked-out file when scanning a subdirectory."""
    root = tmp_path / "repo"
    source = root / "src"
    source.mkdir(parents=True)
    (source / "a.txt").write_text("8.8.8.8", encoding="utf-8")
    monkeypatch.chdir(root)
    found = discover_indicators(source)
    assert found[0].locations[0].file_path == "src/a.txt"
