"""Tests for GitHub Actions summary and annotation helpers."""

from pathlib import Path
from unittest.mock import patch

from network_reputation_check.gh_summary import write_check_annotations, write_summary


def test_write_check_annotations_emits_notice_for_clean_vt() -> None:
    """Ensure clean VirusTotal result emits a notice annotation."""
    result = {"stats": {"malicious": 0, "suspicious": 0}}

    with patch("network_reputation_check.gh_summary.click.echo") as mock_echo, patch.dict(
        "os.environ", {"GITHUB_ACTIONS": "true"},
    ):
        write_check_annotations(result, "virustotal", "example.com")

    mock_echo.assert_called_once()
    assert "::notice" in mock_echo.call_args[0][0]


def test_write_check_annotations_emits_error_for_threats() -> None:
    """Ensure malicious/suspicious VT result emits an error annotation."""
    result = {"stats": {"malicious": 1, "suspicious": 0}}

    with patch("network_reputation_check.gh_summary.click.echo") as mock_echo, patch.dict(
        "os.environ", {"GITHUB_ACTIONS": "true"},
    ):
        write_check_annotations(result, "virustotal", "example.com")

    mock_echo.assert_called_once()
    assert "::error" in mock_echo.call_args[0][0]


def test_write_check_annotations_noop_when_not_in_github_actions() -> None:
    """Ensure no annotations are emitted outside GitHub Actions."""
    result = {"stats": {"malicious": 0, "suspicious": 0}}

    with patch("network_reputation_check.gh_summary.click.echo") as mock_echo, patch.dict("os.environ", {}, clear=True):
        write_check_annotations(result, "virustotal", "example.com")

    mock_echo.assert_not_called()


def test_write_summary_appends_to_summary_file(tmp_path: Path) -> None:
    """Ensure write_summary appends content when GITHUB_STEP_SUMMARY is set."""
    summary_file = tmp_path / "summary.md"
    with patch.dict("os.environ", {"GITHUB_STEP_SUMMARY": str(summary_file)}):
        write_summary("hello")
        write_summary(" world")

    assert summary_file.read_text(encoding="utf-8") == "hello world"
