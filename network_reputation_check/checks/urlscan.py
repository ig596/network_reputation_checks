"""Module for the URLScan reputation check."""

from typing import Any

import requests

from network_reputation_check.checks.base import ReputationCheck
from network_reputation_check.constants import Source
from network_reputation_check.utils import is_domain


class URLScanCheck(ReputationCheck):
    """Reputation check implementation for URLScan."""

    def name(self) -> str:
        """Return the name of the source."""
        return Source.URLSCAN.value

    def run(self, target: str, api_key: str | None = None) -> dict[str, Any]:
        """Run the URLScan reputation check.

        Args:
        ----
            target: The domain to check.
            api_key: The API key for URLScan.

        Returns:
        -------
            A dictionary containing the results or an error message.

        """
        if not api_key:
            return {"error": "Missing URLScan API key"}

        if not is_domain(target):
            return {"error": "URLScan only supports domain lookups"}

        headers = {"API-Key": api_key}
        try:
            response = requests.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{target}",
                headers=headers,
                timeout=10,  # Add timeout to prevent hanging requests
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": f"URLScan API error: {e}"}
