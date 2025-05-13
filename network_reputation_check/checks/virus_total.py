"""Module for the VirusTotal reputation check."""

from collections.abc import Callable
from typing import Any

import vt

from network_reputation_check.checks.base import ReputationCheck
from network_reputation_check.constants import Source
from network_reputation_check.utils import is_domain, is_ip


def parse_virustotal_response(obj: vt.Object) -> dict[str, Any]:
    """Parse the VirusTotal API response into a dictionary.

    Args:
    ----
        obj: The VirusTotal object returned by the API.

    Returns:
    -------
        A dictionary containing the parsed response.

    """
    stats = obj.last_analysis_stats
    results = obj.last_analysis_results

    detections = [
        {
            "engine": engine,
            "category": result.get("category", "undetected"),
            "result": result.get("result", "clean"),
        }
        for engine, result in results.items()
    ]

    return {
        "target": obj.id,
        "type": obj.type,
        "last_analysis_date": obj.get("last_analysis_date"),
        "stats": stats,
        "detections": detections,
    }


class VirusTotalCheck(ReputationCheck):
    """Reputation check implementation for VirusTotal."""

    def __init__(self, client_factory: Callable[[str], vt.Client] | None = None) -> None:
        """Initialize the VirusTotalCheck.

        Args:
        ----
            client_factory: A callable to create a VirusTotal client.

        """
        self._client_factory = client_factory or (lambda key: vt.Client(key))

    def name(self) -> str:
        """Return the name of the source."""
        return Source.VIRUSTOTAL.value

    def run(self, target: str, api_key: str | None = None) -> dict[str, Any]:
        """Run the VirusTotal reputation check.

        Args:
        ----
            target: The IP or domain to check.
            api_key: The API key for VirusTotal.

        Returns:
        -------
            A dictionary containing the results or an error message.

        """
        if not api_key:
            return {"error": "Missing VirusTotal API key"}

        try:
            with self._client_factory(api_key) as client:
                if is_domain(target):
                    obj = client.get_object(f"/domains/{target}")
                elif is_ip(target):
                    obj = client.get_object(f"/ip_addresses/{target}")
                else:
                    return {"error": "Unsupported target type"}

                return parse_virustotal_response(obj)

        except vt.APIError as e:
            return {"error": f"VirusTotal API error: {e}"}
