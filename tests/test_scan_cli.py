"""Regression tests for scan outcomes, artifacts and action argument handling."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from network_reputation_check.action_entrypoint import action_args
from network_reputation_check.main import cli, emit_annotation


@pytest.mark.parametrize(
    ("response", "expected_code"),
    [
        ({"stats": {"malicious": 0, "suspicious": 0}}, 0),
        ({"stats": {"malicious": 1, "suspicious": 0}}, 1),
        ({"stats": {"malicious": 0, "suspicious": 1}}, 1),
        ({"error": "Rate limited"}, 1),
    ],
)
@patch("network_reputation_check.checks.virus_total.VirusTotalCheck.run")
def test_scan_outcomes_write_reports(mock_run: MagicMock, tmp_path: Path, response: dict, expected_code: int) -> None:
    """Write findings before exiting, including errors and suspicious results."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.txt").write_text("8.8.8.8", encoding="utf-8")
    mock_run.return_value = response
    raw = tmp_path / "raw.json"
    sarif = tmp_path / "results.sarif"
    result = CliRunner().invoke(cli, [
        "--source", "virustotal", "--api-key", "FAKE", "--scan-path", str(root),
        "--sarif-file", str(sarif), "--output-file", str(raw),
    ])
    assert result.exit_code == expected_code, result.output
    assert json.loads(raw.read_text())[0]["result"] == response
    assert json.loads(sarif.read_text())["runs"][0]["results"]
    if expected_code:
        assert "No threats detected" not in result.output


@patch("network_reputation_check.checks.virus_total.VirusTotalCheck.run")
def test_empty_scan_writes_empty_reports(mock_run: MagicMock, tmp_path: Path) -> None:
    """Keep empty scans uploadable without making requests."""
    root = tmp_path / "repo"
    root.mkdir()
    raw = tmp_path / "raw.json"
    sarif = tmp_path / "results.sarif"
    result = CliRunner().invoke(cli, [
        "--source", "virustotal", "--api-key", "FAKE", "--scan-path", str(root),
        "--sarif-file", str(sarif), "--output-file", str(raw),
    ])
    assert result.exit_code == 0, result.output
    assert json.loads(raw.read_text()) == []
    assert json.loads(sarif.read_text())["runs"][0]["results"] == []
    mock_run.assert_not_called()


@patch("network_reputation_check.checks.virus_total.VirusTotalCheck.run")
def test_scan_limit_prevents_requests(mock_run: MagicMock, tmp_path: Path) -> None:
    """Enforce the provider request cap before any lookup."""
    (tmp_path / "a.txt").write_text("8.8.8.8 1.1.1.1", encoding="utf-8")
    result = CliRunner().invoke(cli, [
        "--source", "virustotal", "--api-key", "FAKE", "--scan-path", str(tmp_path), "--max-indicators", "1",
    ])
    assert result.exit_code != 0
    assert "No lookups were made" in result.output
    mock_run.assert_not_called()


@patch("network_reputation_check.checks.virus_total.VirusTotalCheck.run")
def test_cidr_is_not_sent_to_provider(mock_run: MagicMock, tmp_path: Path) -> None:
    """Report unsupported ranges without a failed or unbounded provider request."""
    (tmp_path / "a.txt").write_text("8.8.4.0/24", encoding="utf-8")
    result = CliRunner().invoke(cli, ["--source", "virustotal", "--api-key", "FAKE", "--scan-path", str(tmp_path)])
    assert result.exit_code == 1
    mock_run.assert_not_called()


@pytest.mark.parametrize("target", ["8.8.8.8\n", "\t8.8.8.8", "8.8.8.8\x00"])
def test_reject_control_characters_before_trimming(target: str) -> None:
    """Do not silently strip invalid input."""
    result = CliRunner().invoke(cli, [target, "--source", "virustotal", "--api-key", "FAKE"])
    assert result.exit_code != 0
    assert "invalid control characters" in result.output


def test_annotation_properties_escape_delimiters() -> None:
    """Keep commas and colons in file names out of annotation properties."""
    with patch.dict("os.environ", {"GITHUB_ACTIONS": "true"}), patch(
        "network_reputation_check.main.click.echo",
    ) as echo:
        emit_annotation("error", "a,line=5:%.txt\n", 1, "bad\nmessage")
    assert "file=a%2Cline=5%3A%25.txt%0A,line=1::bad%0Amessage" in echo.call_args.args[0]


def test_action_omits_empty_inputs() -> None:
    """Leave optional inputs out instead of passing empty positional arguments."""
    with patch.dict("os.environ", {"NRC_SOURCE": "virustotal", "NRC_TARGET": "8.8.8.8"}, clear=True):
        assert action_args() == ["8.8.8.8", "--source", "virustotal"]


@patch("network_reputation_check.checks.virus_total.VirusTotalCheck.run")
def test_action_single_target_remains_compatible(mock_run: MagicMock) -> None:
    """Run a single-target action through its translated inputs."""
    mock_run.return_value = {"stats": {"malicious": 0, "suspicious": 0}}
    with patch.dict("os.environ", {
        "NRC_SOURCE": "virustotal", "NRC_TARGET": "8.8.8.8", "NRC_API_KEY": "FAKE",
    }, clear=True):
        result = CliRunner().invoke(cli, action_args())
    assert result.exit_code == 0, result.output
    mock_run.assert_called_once_with("8.8.8.8", api_key="FAKE")
