"""Translate Docker action inputs into CLI arguments without empty placeholders."""

import os
import sys

from network_reputation_check.main import cli


def action_args() -> list[str]:
    """Preserve each input as one argument without shell interpolation."""
    args: list[str] = []
    target = os.getenv("NRC_TARGET", "")
    if target:
        args.append(target)
    for name in ("source", "api-key", "scan-path", "sarif-file", "output-file", "max-indicators"):
        value = os.getenv("NRC_" + name.upper().replace("-", "_"), "")
        if value:
            args.extend(("--" + name, value))
    return args


if __name__ == "__main__":
    cli.main(args=sys.argv[1:] or action_args())
