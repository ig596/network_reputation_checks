"""Tests for the VirusTotal and URLScan reputation checks."""

from unittest.mock import MagicMock, patch

import pytest

from network_reputation_check.checks.base import ReputationCheck
from network_reputation_check.checks.urlscan import URLScanCheck
from network_reputation_check.checks.virus_total import VirusTotalCheck


@pytest.mark.parametrize(
    ("check_class", "api_key"),
    [
        (VirusTotalCheck, "FAKE_VT_KEY"),
        (URLScanCheck, "FAKE_URLSCAN_KEY"),
    ],
)
@patch("network_reputation_check.checks.virus_total.vt.Client")
@patch("requests.get")
def test_check_run(
    mock_get: MagicMock,
    mock_vt_client: MagicMock,
    check_class: type[ReputationCheck],
    api_key: str,
) -> None:
    """Test the run method of reputation checks.

    Args:
    ----
        mock_get: Mocked `requests.get` function for URLScan.
        mock_vt_client: Mocked VirusTotal client.
        check_class: The reputation check class to test.
        api_key: The API key for the reputation check.

    """
    mock_get.return_value.ok = True
    mock_get.return_value.json.return_value = {
        "status": "ok",
        "stats": {"malicious": 0, "suspicious": 0},
    }

    if check_class == VirusTotalCheck:
        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get_object.return_value = MagicMock(
            id="example.com",
            type="domain",
            last_analysis_stats={"malicious": 0, "suspicious": 0},
            last_analysis_results={},
        )
        mock_vt_client.return_value = mock_client_instance

    checker = check_class()
    result = checker.run("example.com", api_key=api_key)
    assert isinstance(result, dict)
    assert "error" not in result
    assert result.get("stats", {}).get("malicious") == 0


def test_virustotal_check() -> None:
    """Test the name method of VirusTotalCheck."""
    check = VirusTotalCheck()
    assert check.name() == "virustotal"


def test_urlscan_check() -> None:
    """Test the name method of URLScanCheck."""
    check = URLScanCheck()
    assert check.name() == "urlscan"
