"""SARIF output helpers for reputation scan findings."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from network_reputation_check.scanner import IndicatorCandidate

SARIF_VERSION = "2.1.0"


def classify_level(result: dict[str, Any]) -> str:
    """Map a source result to SARIF level."""
    stats = result.get("stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))

    if malicious > 0:
        return "error"
    if suspicious > 0:
        return "warning"
    if harmless > 0 or result.get("results"):
        return "note"
    return "warning"


def _result_message(level: str, source: str, indicator: IndicatorCandidate, result: dict[str, Any]) -> str:
    stats = result.get("stats", {})
    return (
        f"{source} check for {indicator.kind} '{indicator.value}' => {level}. "
        f"stats={stats if stats else 'n/a'}"
    )


def build_sarif_run(source: str, scanned: list[tuple[IndicatorCandidate, dict[str, Any]]]) -> dict[str, Any]:
    """Build a SARIF JSON document for all scanned indicators."""
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}

    for indicator, check_result in scanned:
        if check_result.get("error"):
            level = "warning"
            rule_id = f"{source}-lookup-error"
            message = f"Lookup error for {indicator.value}: {check_result['error']}"
        else:
            level = classify_level(check_result)
            rule_id = f"{source}-{level}"
            message = _result_message(level, source, indicator, check_result)

        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"{source} reputation result: {level}"},
            },
        )

        results.extend(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location.file_path},
                            "region": {"startLine": location.line},
                        },
                    },
                ],
            }
            for location in indicator.locations
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "network-reputation-check",
                        "informationUri": "https://github.com/ig596/network_reputation_checks",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
            },
        ],
    }
