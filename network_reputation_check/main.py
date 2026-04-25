"""network_reputation_check.main.

CLI entry-point for the network-reputation-check tool.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import click

from network_reputation_check.checks import get_all_checks
from network_reputation_check.gh_summary import write_summary
from network_reputation_check.renderers import render_markdown, render_terminal
from network_reputation_check.sarif import build_sarif_run, classify_level
from network_reputation_check.scanner import discover_indicators


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def in_github_actions() -> bool:
    """Return True if running inside a GitHub Actions environment."""
    return os.getenv("GITHUB_ACTIONS", "").lower() == "true"


def emit_annotation(level: str, file_path: str, line: int, message: str) -> None:
    """Emit a GitHub Actions workflow annotation if applicable."""
    if not in_github_actions():
        return

    if level == "error":
        annotation_type = "error"
    elif level == "warning":
        annotation_type = "warning"
    else:
        annotation_type = "notice"

    safe_file_path = _escape_workflow_command_value(file_path)
    safe_message = _escape_workflow_command_value(message)
    click.echo(f"::{annotation_type} file={safe_file_path},line={line}::{safe_message}")


def _escape_workflow_command_value(value: str) -> str:
    """Escape workflow command values to prevent command injection."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def sanitize_target(value: str | None) -> str | None:
    """Sanitize user-provided target input."""
    if value is None:
        return None
    cleaned = value.strip()
    if any(ch in cleaned for ch in ("\r", "\n", "\t")):
        msg = "Error: Target contains invalid control characters."
        raise click.BadParameter(msg)
    return cleaned


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
logger = logging.getLogger(__name__)


@click.command()
@click.argument("target", required=False)
@click.option(
    "--source",
    required=True,
    help="Source to use for reputation check (e.g., virustotal, urlscan).",
)
@click.option(
    "--api-key",
    envvar="API_KEY",
    help="API key for the selected source (required for VirusTotal, optional for urlscan.io).",
    required=False,
)
@click.option(
    "--output-file",
    type=click.Path(writable=True),
    help="Write raw JSON result to this file.",
)
@click.option(
    "--scan-path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Scan a repository path for indicators and run checks on all discovered items.",
)
@click.option(
    "--sarif-file",
    type=click.Path(writable=True, path_type=Path),
    help="Write SARIF results to this file (recommended for PR code scanning annotations).",
)
def cli(  # noqa: C901, PLR0912, PLR0913, PLR0915
    target: str | None,
    source: str,
    api_key: str | None,
    output_file: Path | None,
    scan_path: Path | None,
    sarif_file: Path | None,
) -> None:
    """Run a single-target check or a repository scan in CI-friendly mode."""
    error_messages = {
        "missing_target": "Error: Target is required unless --scan-path is provided.",
        "missing_source": "Error: Source is required.",
        "unsupported_source": lambda s, keys: f"Error: Unsupported source '{s}'. Supported sources: {', '.join(keys)}.",
        "missing_api_key": "Error: VirusTotal requires an API key.",
    }

    if not source:
        click.echo(error_messages["missing_source"], err=True)
        raise click.BadParameter(error_messages["missing_source"])

    target = sanitize_target(target)

    checks: dict[str, Any] = get_all_checks()
    if source not in checks:
        unsupported_source_msg = error_messages["unsupported_source"](source, checks.keys())
        click.echo(unsupported_source_msg, err=True)
        raise click.BadParameter(unsupported_source_msg)

    if source == "virustotal" and not api_key:
        logger.error(error_messages["missing_api_key"])
        click.echo(error_messages["missing_api_key"], err=True)
        sys.exit(1)

    check = checks[source]

    if scan_path:
        candidates = discover_indicators(scan_path)
        if not candidates:
            click.echo("No scanable indicators found.")
            if sarif_file:
                sarif_payload = build_sarif_run(source, [])
                with sarif_file.open("w", encoding="utf-8") as fp:
                    json.dump(sarif_payload, fp, indent=2)
            sys.exit(0)

        scanned: list[tuple[Any, dict[str, Any]]] = []
        failure = False
        for candidate in candidates:
            result: dict[str, Any] = check.run(candidate.value, api_key=api_key or "")
            scanned.append((candidate, result))

            level = "warning" if result.get("error") else classify_level(result)
            if level == "error":
                failure = True

            for location in candidate.locations:
                emit_annotation(level, location.file_path, location.line, f"[{source}] {candidate.value} -> {level}")

        if output_file:
            with output_file.open("w", encoding="utf-8") as fp:
                json.dump(
                    [
                        {
                            "value": candidate.value,
                            "kind": candidate.kind,
                            "locations": [hit.__dict__ for hit in candidate.locations],
                            "result": result,
                        }
                        for candidate, result in scanned
                    ],
                    fp,
                    indent=2,
                )

        if sarif_file:
            sarif_payload = build_sarif_run(source, scanned)
            with sarif_file.open("w", encoding="utf-8") as fp:
                json.dump(sarif_payload, fp, indent=2)

        if failure:
            click.echo("❌ Threats detected - failing job.", err=True)
            sys.exit(1)

        click.echo("✅ No threats detected.")
        sys.exit(0)

    if not target:
        click.echo(error_messages["missing_target"], err=True)
        raise click.BadParameter(error_messages["missing_target"])

    result = check.run(target, api_key=api_key or "")

    if "error" in result:
        logger.error(f"Error encountered: {result['error']}")
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
        click.echo("❌ Threats detected - failing job.", err=True)
        sys.exit(1)

    click.echo("✅ No threats detected.")
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    cli()
