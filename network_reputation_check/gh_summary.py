"""Module for writing GitHub Actions job summaries."""

import os
from pathlib import Path


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
