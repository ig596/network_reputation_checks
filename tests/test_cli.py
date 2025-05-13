"""Tests for the CLI of the network reputation check tool."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from network_reputation_check.main import cli


@pytest.mark.parametrize(
    ("source", "api_key", "expected"),
    [
        (
            "virustotal",
            "FAKE_VT_KEY",
            {
                "mock_response": {"stats": {"malicious": 0, "suspicious": 0}},
                "expected_output": "✅ No threats detected.",
                "expected_exit_code": 0,
            },
        ),
        (
            "virustotal",
            "FAKE_VT_KEY",
            {
                "mock_response": {"stats": {"malicious": 1, "suspicious": 0}},
                "expected_output": "❌ Threats detected - failing job.",
                "expected_exit_code": 1,
            },
        ),
        (
            "virustotal",
            None,
            {
                "mock_response": {"error": "Missing VirusTotal API key"},
                "expected_output": "Error: Missing VirusTotal API key",
                "expected_exit_code": 1,
            },
        ),
        (
            "urlscan",
            "FAKE_URLSCAN_KEY",
            {
                "mock_response": {"results": [{"task": {"url": "example.com"}, "page": {"status": "ok"}}]},
                "expected_output": "✅ No threats detected.",
                "expected_exit_code": 0,
            },
        ),
        (
            "urlscan",
            None,
            {
                "mock_response": {"error": "Missing URLScan API key"},
                "expected_output": "Error: Missing URLScan API key",
                "expected_exit_code": 1,
            },
        ),
    ],
)
@patch("network_reputation_check.checks.virus_total.VirusTotalCheck.run")
@patch("network_reputation_check.checks.urlscan.URLScanCheck.run")
def test_cli_runs(
    mock_urlscan_run: MagicMock,
    mock_virustotal_run: MagicMock,
    source: str,
    api_key: str | None,
    expected: dict[str, str | int],
) -> None:
    """Test the CLI with various sources and scenarios.

    Args:
    ----
        mock_urlscan_run: Mocked URLScanCheck.run method.
        mock_virustotal_run: Mocked VirusTotalCheck.run method.
        source: The source to use for the reputation check.
        api_key: The API key for the source.
        expected: A dictionary containing the mocked response, expected output, and expected exit code.

    """
    mock_response = expected["mock_response"]
    expected_output = expected["expected_output"]
    expected_exit_code = expected["expected_exit_code"]

    mock_run = mock_virustotal_run if source == "virustotal" else mock_urlscan_run
    mock_run.return_value = mock_response

    runner = CliRunner()
    args = ["example.com", "--source", source]
    if api_key:
        args.extend(["--api-key", api_key])
    result = runner.invoke(cli, args)

    assert expected_output in result.output
    assert result.exit_code == expected_exit_code


def test_cli_invalid_source() -> None:
    """Test the CLI with an unsupported source."""
    runner = CliRunner()
    result = runner.invoke(cli, ["example.com", "--source", "invalid-source"])
    assert "Error: Unsupported source 'invalid-source'" in result.output
    assert result.exit_code != 0


def test_cli_missing_target() -> None:
    """Test the CLI with a missing target argument."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--source", "virustotal"])
    assert "Error: Missing argument 'TARGET'" in result.output
    assert result.exit_code != 0
