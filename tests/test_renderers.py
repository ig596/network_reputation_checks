"""Tests for result rendering helpers."""

from network_reputation_check.renderers import (
    format_timestamp,
    render_markdown,
    render_terminal,
    render_virustotal_markdown,
    render_virustotal_terminal,
)


def test_format_timestamp_returns_utc_string() -> None:
    """Ensure UTC timestamp formatting does not error and includes UTC suffix."""
    assert format_timestamp(1) == "1970-01-01 00:00:01 UTC"


def test_virustotal_renderers_handle_non_malicious_detections() -> None:
    """Ensure renderers do not output empty detection tables when detections are all non-malicious."""
    result = {
        "target": "example.com",
        "type": "domain",
        "last_analysis_date": None,
        "stats": {"malicious": 0, "suspicious": 1},
        "detections": [
            {"engine": "EngineA", "category": "undetected", "result": "clean"},
        ],
    }

    terminal_output = render_virustotal_terminal(result)
    markdown_output = render_virustotal_markdown(result)

    assert "No malicious detections found." in terminal_output
    assert "_No malicious detections found._" in markdown_output


def test_render_terminal_uses_rich_virustotal_renderer() -> None:
    """Ensure generic render function routes to the rich VT renderer."""
    result = {
        "target": "example.com",
        "type": "domain",
        "last_analysis_date": None,
        "stats": {"malicious": 0, "suspicious": 0},
        "detections": [],
    }

    output = render_terminal(result, "virustotal")
    assert "VirusTotal Reputation Report" in output


def test_render_markdown_urlscan_includes_table() -> None:
    """Ensure URLScan markdown output includes top-match rows."""
    result = {
        "results": [
            {
                "task": {"time": "2026-04-25T00:00:00.000Z", "url": "https://example.com"},
                "page": {"ip": "1.1.1.1", "status": "200"},
            },
        ],
    }

    output = render_markdown(result, "urlscan")
    assert "| Scan Time | URL | Resolved IP | HTTP Status |" in output
    assert "https://example.com" in output


def test_render_terminal_urlscan_includes_header() -> None:
    """Ensure URLScan terminal render includes report header and count."""
    output = render_terminal({"results": []}, "urlscan")
    assert "URLScan Reputation Report" in output
    assert "Matches found : 0" in output


def test_unknown_source_render_fallbacks() -> None:
    """Ensure unknown source falls back with a clear message."""
    terminal_output = render_terminal({}, "unknown")
    markdown_output = render_markdown({}, "unknown")

    assert "Unknown source 'unknown'" in terminal_output
    assert "No rendering available" in markdown_output
