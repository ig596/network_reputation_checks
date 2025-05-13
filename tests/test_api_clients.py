"""Unit tests for the VirusTotal and URLScan client wrappers."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
import requests
import vt

from network_reputation_check.checks.urlscan import URLScanCheck
from network_reputation_check.checks.virus_total import VirusTotalCheck

if TYPE_CHECKING:
    from network_reputation_check.checks.base import ReputationCheck


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _stub_vt_object(target: str, obj_type: str, malicious: int = 0) -> MagicMock:
    """Create a fake vt.Object with the minimal attrs our code reads."""
    fake = MagicMock(spec=vt.object.Object)
    fake.id = target
    fake.type = obj_type
    fake.last_analysis_stats = {"malicious": malicious, "suspicious": 0}
    fake.last_analysis_results = {}
    fake.get.return_value = None  # for .get("last_analysis_date")
    return fake


# --------------------------------------------------------------------------- #
# Happy-path tests
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("checker_class", "target", "api_key"),
    [
        (VirusTotalCheck, "1.1.1.1", "fake_vt_key"),
        (VirusTotalCheck, "example.com", "fake_vt_key"),
        (URLScanCheck, "example.com", "fake_urlscan_key"),
    ],
)
def test_api_client_returns_ok(
    checker_class: type[ReputationCheck],
    target: str,
    api_key: str | None,
) -> None:
    """Ensure clients return a dict and no error on happy path."""
    if checker_class is VirusTotalCheck:
        # Patch vt.Client so no network happens
        with patch(
            "network_reputation_check.checks.virus_total.vt.Client",
        ) as mock_client_cls:
            fake_obj = _stub_vt_object(target, "ip_address" if ":" not in target else "domain")
            mock_client_cls.return_value.__enter__.return_value.get_object.return_value = fake_obj
            checker = checker_class()
            result = checker.run(target, api_key=api_key)
    else:  # URLScanCheck still uses requests
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.ok = True
            mock_resp.json.return_value = {"status": "ok"}
            mock_get.return_value = mock_resp
            checker = checker_class()
            result = checker.run(target, api_key=api_key)

    assert isinstance(result, dict)
    # VirusTotal returns stats; URLScan returns status
    assert "error" not in result


# --------------------------------------------------------------------------- #
# Error-path tests
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("checker_class", "target", "api_key"),
    [
        (VirusTotalCheck, "example.com", "invalid"),
        (URLScanCheck, "example.com", "invalid"),
    ],
)
def test_api_client_handles_errors(
    checker_class: type[ReputationCheck],
    target: str,
    api_key: str | None,
) -> None:
    """Ensure clients surface a useful 'error' key on API failure."""
    if checker_class is VirusTotalCheck:
        with patch(
            "network_reputation_check.checks.virus_total.vt.Client",
        ) as mock_client_cls:
            # make the client raise WrongCredentialsError
            mock_client_cls.side_effect = vt.APIError("WrongCredentialsError", "Wrong API key")
            checker = checker_class()
            result = checker.run(target, api_key=api_key)
    else:
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.ok = False
            mock_resp.status_code = 403
            mock_resp.text = "Forbidden"
            mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError("403")
            mock_get.return_value = mock_resp
            checker = checker_class()
            result = checker.run(target, api_key=api_key)

    assert isinstance(result, dict)
    assert "error" in result
