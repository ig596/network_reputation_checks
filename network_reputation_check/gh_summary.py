"""Helpers for GitHub Actions output (summary + annotations)."""

import os
from pathlib import Path
from typing import Any

import click


def write_summary(content: str) -> None:
    """Write content to the GitHub Actions job summary file.

    This function appends the provided content to the file specified by the
    GITHUB_STEP_SUMMARY environment variable. If the variable is not set,
    the function does nothing.

    Args:
    ----
        content: The content to write to the summary file.

    """
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_file:
        summary_path = Path(summary_file)
        with summary_path.open("a", encoding="utf-8") as f:
            f.write(content)


def write_check_annotations(result: dict[str, Any], source: str, target: str) -> None:
    """Emit GitHub Actions workflow command annotations.

    This writes `::notice` / `::error` commands so users get quick, visible
    status in job logs and the Checks UI.
    """
    if os.getenv("GITHUB_ACTIONS", "").lower() != "true":
        return

    if source != "virustotal":
        click.echo(f"::notice title=Reputation Check::{source} check completed for {target}.")
        return

    stats = result.get("stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))

    if malicious > 0 or suspicious > 0:
        click.echo(
            "::error title=Threats detected::"
            f"{target} has malicious={malicious}, suspicious={suspicious} detections.",
        )
    else:
        click.echo(f"::notice title=No threats detected::{target} has no malicious or suspicious detections.")
