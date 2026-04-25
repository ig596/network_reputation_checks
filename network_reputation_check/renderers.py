"""Renderers for formatting reputation check results.

This module provides functions to render results in terminal-friendly and Markdown formats
for different reputation check sources like VirusTotal and urlscan.io.
"""

import logging
from datetime import UTC, datetime
from typing import Any

from tabulate import tabulate

logger = logging.getLogger(__name__)


def format_timestamp(ts: int | None) -> str:
    """Format a Unix timestamp into a human-readable UTC string.

    Args:
    ----
        ts: The Unix timestamp to format.

    Returns:
    -------
        A string representing the formatted timestamp in UTC, or "N/A" if the timestamp is None.

    """
    if not ts:
        return "N/A"
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_virustotal_terminal(result: dict[str, Any]) -> str:
    """Render a human-friendly terminal output for VirusTotal results.

    Args:
    ----
        result: The VirusTotal API response as a dictionary.

    Returns:
    -------
        A string representing the formatted terminal output.

    """
    stats = result.get("stats", {})
    detections = result.get("detections", [])

    lines = [
        "🛡️  VirusTotal Reputation Report",
        f"{'-' * 40}",
        f"Target            : {result.get('target')}",
        f"Type              : {result.get('type')}",
        f"Last Analyzed     : {format_timestamp(result.get('last_analysis_date'))}",
        "",
        "Analysis Statistics:",
    ]

    for key, val in stats.items():
        lines.append(f"  {key.capitalize():<12}: {val}")

    malicious_detections = [d for d in detections if d.get("category") == "malicious"]
    if malicious_detections:
        lines.append("\nDetected Engines:")
        table = [[d["engine"], d["category"], d["result"]] for d in malicious_detections]
        lines.append(tabulate(table, headers=["Engine", "Category", "Result"]))
    else:
        lines.append("\nNo malicious detections found.")

    return "\n".join(lines)


def render_virustotal_markdown(result: dict[str, Any]) -> str:
    """Render a Markdown summary for VirusTotal results.

    Args:
    ----
        result: The VirusTotal API response as a dictionary.

    Returns:
    -------
        A string representing the formatted Markdown output.

    """
    stats = result.get("stats", {})
    detections = result.get("detections", [])

    md = [
        f"### 🛡️ VirusTotal Reputation Report for `{result.get('target')}`\n",
        f"**Type**: `{result.get('type')}`  \n",
        f"**Last Analyzed**: `{format_timestamp(result.get('last_analysis_date'))}`\n",
        "**Analysis Statistics:**\n",
    ]

    for key, val in stats.items():
        md.append(f"- **{key.capitalize()}**: {val}")

    malicious_detections = [d for d in detections if d.get("category") == "malicious"]
    if malicious_detections:
        md.append("\n**Detected Engines:**\n")
        md.append("| Engine | Category | Result |")
        md.append("|--------|----------|--------|")
        md.extend(f"| {d['engine']} | {d['category']} | {d['result']} |" for d in malicious_detections)
    else:
        md.append("\n_No malicious detections found._")

    return "\n".join(md)


def render_terminal(result: dict[str, Any], source: str) -> str:
    """Render a human-friendly terminal output based on the source.

    Args:
    ----
        result: The API response as a dictionary.
        source: The source of the reputation check (e.g., "virustotal", "urlscan").

    Returns:
    -------
        A string representing the formatted terminal output.

    """
    if "error" in result:
        return f"Error: {result['error']}"

    if source == "virustotal":
        return render_virustotal_terminal(result)

    if source == "urlscan":
        results = result.get("results", [])
        lines = [
            "🔎 URLScan Reputation Report",
            f"{'-' * 40}",
            f"Matches found : {len(results)}",
        ]

        top_hits = results[:5]
        if top_hits:
            lines.append("\nTop Matches:")
            rows = [
                [
                    hit.get("task", {}).get("time", "N/A"),
                    hit.get("task", {}).get("url", "N/A"),
                    hit.get("page", {}).get("ip", "N/A"),
                    hit.get("page", {}).get("status", "N/A"),
                ]
                for hit in top_hits
            ]
            lines.append(tabulate(rows, headers=["Scan Time", "URL", "Resolved IP", "HTTP Status"]))

        return "\n".join(lines)

    logger.warning(f"Unknown source '{source}' encountered in render_terminal.")
    return f"Unknown source '{source}'. No rendering available."


def render_markdown(result: dict[str, Any], source: str) -> str:
    """Render a Markdown summary based on the source.

    Args:
    ----
        result: The API response as a dictionary.
        source: The source of the reputation check (e.g., "virustotal", "urlscan").

    Returns:
    -------
        A string representing the formatted Markdown output.

    """
    if source == "virustotal":
        return render_virustotal_markdown(result)

    if source == "urlscan":
        results = result.get("results", [])
        md = [
            "### 🔎 URLScan Reputation Report",
            f"- Found **{len(results)}** results for the target.",
        ]
        top_hits = results[:5]
        if top_hits:
            md.extend(
                [
                    "",
                    "| Scan Time | URL | Resolved IP | HTTP Status |",
                    "|---|---|---|---|",
                ],
            )
            md.extend(
                (
                    f"| {hit.get('task', {}).get('time', 'N/A')} "
                    f"| {hit.get('task', {}).get('url', 'N/A')} "
                    f"| {hit.get('page', {}).get('ip', 'N/A')} "
                    f"| {hit.get('page', {}).get('status', 'N/A')} |"
                )
                for hit in top_hits
            )
        return "\n".join(md) + "\n"

    logger.warning(f"Unknown source '{source}' encountered in render_markdown.")
    return f"### Unknown Source\nNo rendering available for source '{source}'."
