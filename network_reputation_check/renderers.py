"""Renderers for formatting reputation check results.

This module provides functions to render results in terminal-friendly and Markdown formats
for different reputation check sources like VirusTotal and urlscan.io.
"""

import logging
from datetime import datetime
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
    return datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


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
        f"{'-'*40}",
        f"Target            : {result.get('target')}",
        f"Type              : {result.get('type')}",
        f"Last Analyzed     : {format_timestamp(result.get('last_analysis_date'))}",
        "",
        "Analysis Statistics:",
    ]

    for key, val in stats.items():
        lines.append(f"  {key.capitalize():<12}: {val}")

    if detections:
        lines.append("\nDetected Engines:")
        table = [[d["engine"], d["category"], d["result"]] for d in detections if d["category"] == "malicious"]
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

    if detections:
        md.append("\n**Detected Engines:**\n")
        md.append("| Engine | Category | Result |")
        md.append("|--------|----------|--------|")
        md.extend(
            f"| {d['engine']} | {d['category']} | {d['result']} |"
            for d in detections
            if d["category"] == "malicious"
        )
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
        stats = result.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        lines = [
            "VirusTotal Report:",
            f"  Malicious: {malicious}",
            f"  Suspicious: {suspicious}",
        ]

        if malicious > 0 or suspicious > 0:
            lines.append("❌ Threats detected - failing job.")
        else:
            lines.append("✅ No threats detected.")

        return "\n".join(lines)

    if source == "urlscan":
        results = result.get("results", [])
        return f"URLScan Report:\n  Found {len(results)} results for the target.\n"

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
        stats = result.get("stats", {})
        return (
            f"### VirusTotal Report\n"
            f"- **Malicious**: {stats.get('malicious', 0)}\n"
            f"- **Suspicious**: {stats.get('suspicious', 0)}\n"
        )
    if source == "urlscan":
        results = result.get("results", [])
        return f"### URLScan Report\n- Found **{len(results)}** results for the target.\n"

    logger.warning(f"Unknown source '{source}' encountered in render_markdown.")
    return f"### Unknown Source\nNo rendering available for source '{source}'."
