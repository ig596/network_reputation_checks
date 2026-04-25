"""Codebase indicator discovery utilities."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from network_reputation_check.utils import is_cidr, is_domain, is_ip

if TYPE_CHECKING:
    from pathlib import Path

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CIDR_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/(?:[0-9]|[1-2][0-9]|3[0-2])\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}\b")

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
MAX_SCAN_FILE_SIZE_BYTES = 1_000_000
RESERVED_DOMAIN_SUFFIXES = {
    ".alt",
    ".arpa",
    ".example",
    ".home",
    ".internal",
    ".invalid",
    ".lan",
    ".local",
    ".localhost",
    ".localdomain",
    ".test",
}


@dataclass(frozen=True)
class IndicatorHit:
    """An indicator discovered in a repository file."""

    value: str
    kind: str
    file_path: str
    line: int


@dataclass(frozen=True)
class IndicatorCandidate:
    """A deduplicated indicator with all source locations."""

    value: str
    kind: str
    locations: tuple[IndicatorHit, ...]


def sanitize_indicator_value(value: str) -> str:
    """Normalize an extracted indicator token before validation."""
    return value.strip().strip("\"'()[]{}<>,;").replace("\r", "").replace("\n", "").replace("\t", "")


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_public_cidr(value: str) -> bool:
    net = ipaddress.ip_network(value, strict=False)
    return not (
        net.is_private
        or net.is_loopback
        or net.is_link_local
        or net.is_multicast
        or net.is_reserved
        or net.is_unspecified
    )


def should_scan_indicator(value: str) -> bool:
    """Return whether the indicator should be sent to reputation checks."""
    if is_ip(value):
        return _is_public_ip(value)
    if "/" in value and is_cidr(value):
        return _is_public_cidr(value)
    if is_domain(value):
        labels = value.split(".")
        if all(label.isdigit() for label in labels):
            return False
        lowered = value.lower()
        if lowered in {"localhost", "example.com", "example.org", "example.net"}:
            return False
        return not any(lowered.endswith(suffix) for suffix in RESERVED_DOMAIN_SUFFIXES)
    return False


def _iter_files(scan_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in scan_root.rglob("*"):
        if path.is_dir() and path.name in SKIP_DIRS:
            continue
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.stat().st_size > MAX_SCAN_FILE_SIZE_BYTES:
            continue
        files.append(path)
    return files


def discover_indicators(scan_root: Path) -> list[IndicatorCandidate]:  # noqa: C901
    """Discover IP/domain/CIDR indicators from text files in `scan_root`."""
    hits: dict[tuple[str, str], list[IndicatorHit]] = {}

    for file_path in _iter_files(scan_root):
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        relative = str(file_path.relative_to(scan_root))
        for line_no, line in enumerate(content.splitlines(), start=1):
            raw_values: set[str] = set(CIDR_PATTERN.findall(line))
            raw_values.update(IP_PATTERN.findall(line))
            raw_values.update(DOMAIN_PATTERN.findall(line))

            for raw_value in raw_values:
                value = sanitize_indicator_value(raw_value)
                if not value:
                    continue
                kind = ""
                if is_ip(value):
                    kind = "ip"
                elif "/" in value and is_cidr(value):
                    kind = "cidr"
                elif is_domain(value):
                    labels = value.split(".")
                    if all(label.isdigit() for label in labels):
                        continue
                    kind = "domain"
                if not kind or not should_scan_indicator(value):
                    continue

                key = (value, kind)
                hits.setdefault(key, []).append(
                    IndicatorHit(value=value, kind=kind, file_path=relative, line=line_no),
                )

    return [
        IndicatorCandidate(
            value=value,
            kind=kind,
            locations=tuple(sorted(locations, key=lambda h: (h.file_path, h.line))),
        )
        for (value, kind), locations in sorted(hits.items(), key=lambda item: item[0][0])
    ]
