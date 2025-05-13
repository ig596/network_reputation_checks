"""network_reputation_check.main.

CLI entry-point for the network-reputation-check tool.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import click

from network_reputation_check.checks import get_all_checks
from network_reputation_check.gh_summary import write_summary
from network_reputation_check.renderers import render_markdown, render_terminal


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def in_github_actions() -> bool:
    """Return True if running inside a GitHub Actions environment."""
    return os.getenv("GITHUB_ACTIONS", "").lower() == "true"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@click.command()
@click.argument("target")
@click.option(
    "--source",
    required=True,
    help="Source to use for reputation check (e.g., virustotal, urlscan).",
)
@click.option(
    "--api-key",
    envvar="API_KEY",
    help="API key for the selected source (or set API_KEY env).",
    required=False,
)
@click.option(
    "--output-file",
    type=click.Path(writable=True),
    help="Write raw JSON result to this file.",
)
def cli(target: str, source: str, api_key: str | None, output_file: Path | None) -> None:
    """Look up TARGET (IP or domain) in the specified source.

    • Prints a human-friendly terminal report.
    • Automatically appends a Markdown summary to GITHUB_STEP_SUMMARY
      when running inside GitHub Actions.
    • Exits 1 if any malicious or suspicious detections are present.
    """
    checks: dict[str, Any] = get_all_checks()
    if source not in checks:
        click.echo(f"Error: Unsupported source '{source}'. Supported sources: {', '.join(checks.keys())}.", err=True)
        sys.exit(2)

    check = checks[source]
    result: dict[str, Any] = check.run(target, api_key=api_key or "")

    if "error" in result:
        click.echo(f"Error: {result['error']}", err=True)
        sys.exit(1)

    click.echo(render_terminal(result, source))

    if output_file:
        with Path(output_file).open("w", encoding="utf-8") as fp:
            json.dump(result, fp, indent=2)

    if in_github_actions() and os.getenv("GITHUB_STEP_SUMMARY"):
        write_summary(render_markdown(result, source))

    stats: dict[str, int] = result.get("stats", {})
    malicious: int = int(stats.get("malicious", 0))
    suspicious: int = int(stats.get("suspicious", 0))

    if malicious > 0 or suspicious > 0:
        click.echo("❌ Threats detected - failing job.")
        sys.exit(1)

    click.echo("✅ No threats detected.")
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    cli()
