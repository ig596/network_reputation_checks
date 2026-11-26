"""Tests for GitHub Actions reports emitted by the single-target CLI."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from network_reputation_check.main import cli


@patch("network_reputation_check.main.write_check_annotations")
@patch("network_reputation_check.main.write_summary")
@patch("network_reputation_check.checks.virus_total.VirusTotalCheck.run")
def test_cli_writes_github_summary_when_running_in_actions(
    mock_virustotal_run: MagicMock,
    mock_write_summary: MagicMock,
    mock_write_annotations: MagicMock,
    tmp_path: Path,
) -> None:
    """Ensure GitHub summary + annotations are written in Actions environments."""
    mock_virustotal_run.return_value = {"stats": {"malicious": 0, "suspicious": 0}, "detections": []}

    runner = CliRunner()
    env = {"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md")}
    result = runner.invoke(
        cli, ["example.com", "--source", "virustotal", "--api-key", "FAKE_VT_KEY"], env=env,
    )

    assert result.exit_code == 0
    mock_write_summary.assert_called_once()
    mock_write_annotations.assert_called_once()


@patch("network_reputation_check.main.write_check_annotations")
@patch("network_reputation_check.checks.virus_total.VirusTotalCheck.run")
def test_cli_annotations_without_summary_file(mock_run: MagicMock, mock_annotations: MagicMock) -> None:
    """Emit check annotations even when no summary path is available."""
    mock_run.return_value = {"stats": {"malicious": 0, "suspicious": 0}}
    result = CliRunner().invoke(
        cli,
        ["example.com", "--source", "virustotal", "--api-key", "FAKE"],
        env={"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": ""},
    )
    assert result.exit_code == 0
    mock_annotations.assert_called_once()
