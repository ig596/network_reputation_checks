"""Initialization module for reputation check implementations."""

from network_reputation_check.checks.base import ReputationCheck
from network_reputation_check.checks.urlscan import URLScanCheck
from network_reputation_check.checks.virus_total import VirusTotalCheck


def get_all_checks() -> dict[str, ReputationCheck]:
    """Retrieve all available reputation check implementations.

    Returns
    -------
        A dictionary mapping source names to their respective reputation check implementations.

    """
    checks = [
        VirusTotalCheck(),
        URLScanCheck(),
    ]
    return {check.name(): check for check in checks}
