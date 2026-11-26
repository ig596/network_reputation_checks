"""network_reputation_check.main.

CLI entry-point for the network-reputation-check tool.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

import click

from network_reputation_check.checks import get_all_checks
from network_reputation_check.gh_summary import write_summary
from network_reputation_check.renderers import render_markdown, render_terminal
from network_reputation_check.sarif import build_sarif_run, classify_level
from network_reputation_check.scanner import IndicatorCandidate, discover_indicators


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

    safe_file_path = _escape_workflow_command_value(file_path).replace(":", "%3A").replace(",", "%2C")
    safe_message = _escape_workflow_command_value(message)
    click.echo(f"::{annotation_type} file={safe_file_path},line={line}::{safe_message}")


def _escape_workflow_command_value(value: str) -> str:
    """Escape workflow command values to prevent command injection."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def sanitize_target(value: str | None) -> str | None:
    """Sanitize user-provided target input."""
    if value is None:
        return None
    if any(not ch.isprintable() for ch in value):
        msg = "Error: Target contains invalid control characters."
        raise click.BadParameter(msg)
    return value.strip()


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
    type=click.Path(writable=True, dir_okay=False, path_type=Path),
    help="Write raw JSON result to this file.",
)
@click.option(
    "--scan-path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Scan a repository path for indicators and run checks on all discovered items.",
)
@click.option(
    "--sarif-file",
    type=click.Path(writable=True, dir_okay=False, path_type=Path),
    help="Write SARIF results to this file (recommended for PR code scanning annotations).",
)
@click.option(
    "--max-indicators",
    type=click.IntRange(min=1),
    default=100,
    show_default=True,
    help="Refuse scans exceeding this many unique indicators before contacting providers.",
)
def cli(  # noqa: C901, PLR0912, PLR0913, PLR0915
    *,
    target: str | None,
    source: str,
    api_key: str | None,
    output_file: Path | None,
    scan_path: Path | None,
    sarif_file: Path | None,
    max_indicators: int,
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
    if scan_path and target:
        msg = "Choose TARGET or --scan-path, not both."
        raise click.UsageError(msg)
    if not scan_path and not target:
        raise click.UsageError(error_messages["missing_target"])
    if sarif_file and not scan_path:
        msg = "--sarif-file requires --scan-path."
        raise click.UsageError(msg)
    if output_file and sarif_file and output_file.resolve() == sarif_file.resolve():
        msg = "--output-file and --sarif-file must be different paths."
        raise click.UsageError(msg)

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
        excluded = {path for path in (output_file, sarif_file) if path}
        try:
            candidates = discover_indicators(scan_path, excluded_paths=excluded)
        except OSError as exc:
            msg = f"Cannot read scan path: {exc}"
            raise click.ClickException(msg) from exc
        if len(candidates) > max_indicators:
            msg = (
                f"Found {len(candidates)} indicators; limit is {max_indicators}. "
                "Narrow --scan-path or raise --max-indicators. No lookups were made."
            )
            raise click.ClickException(msg)
        scanned: list[tuple[IndicatorCandidate, dict[str, Any]]] = []
        failure = False
        for candidate in candidates:
            if candidate.kind == "cidr":
                result: dict[str, Any] = {"error": "CIDR lookups are not supported; provide individual public IPs."}
            elif source == "urlscan" and candidate.kind != "domain":
                result = {"error": "URLScan only supports domain lookups."}
            else:
                result = check.run(candidate.value, api_key=api_key or "")
            scanned.append((candidate, result))

            level = "warning" if result.get("error") else classify_level(result)
            if result.get("error") or level in {"error", "warning"}:
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
                            "locations": [asdict(hit) for hit in candidate.locations],
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
            click.echo("❌ Threats detected or lookups failed - failing job.", err=True)
            sys.exit(1)

        if not candidates:
            click.echo("No scannable indicators found.")
        else:
            click.echo("✅ No threats detected.")
        sys.exit(0)

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
