"""Discover public network indicators in repository text files."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path

from network_reputation_check.utils import is_domain

# Match CIDRs before IPs so their network address is not also checked separately.
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
IPV6_PATTERN = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]*:){2,}[0-9a-fA-F:.]*(?:/\d{1,3})?")
DOMAIN_PATTERN = re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b")
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
MAX_SCAN_FILE_SIZE_BYTES = 1_000_000
RESERVED_DOMAIN_SUFFIXES = {
    "alt",
    "arpa",
    "example",
    "home",
    "internal",
    "invalid",
    "lan",
    "local",
    "localhost",
    "localdomain",
    "test",
}
EXAMPLE_DOMAINS = {"example.com", "example.org", "example.net"}


@dataclass(frozen=True)
class IndicatorHit:
    """A source location for an indicator."""

    value: str
    kind: str
    file_path: str
    line: int


@dataclass(frozen=True)
class IndicatorCandidate:
    """An indicator with all of its source locations."""

    value: str
    kind: str
    locations: tuple[IndicatorHit, ...]


def sanitize_indicator_value(value: str) -> str:
    """Remove token wrappers and normalize domain casing."""
    return value.strip().strip("\"'()[]{}<>,;").lower()


def _indicator_kind(value: str) -> str:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
            return "cidr"
        ipaddress.ip_address(value)
    except ValueError:
        return "domain" if is_domain(value) else ""
    return "ip"


def should_scan_indicator(value: str) -> bool:
    """Exclude private networks and reserved example/local domain names."""
    kind = _indicator_kind(value)
    if kind == "ip":
        address = ipaddress.ip_address(value)
        return address.is_global and not address.is_multicast
    if kind == "cidr":
        network = ipaddress.ip_network(value, strict=False)
        return network.is_global and not network.is_multicast
    if kind == "domain":
        lowered = value.lower()
        return lowered.split(".")[-1] not in RESERVED_DOMAIN_SUFFIXES and not any(
            lowered == name or lowered.endswith("." + name) for name in EXAMPLE_DOMAINS
        )
    return False


def _raise_walk_error(error: OSError) -> None:
    raise error


def _iter_files(scan_root: Path, excluded_paths: set[Path]) -> list[Path]:
    files: list[Path] = []
    for directory, dirs, names in os.walk(scan_root, followlinks=False, onerror=_raise_walk_error):
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file() or path.resolve() in excluded_paths:
                continue
            if path.stat().st_size <= MAX_SCAN_FILE_SIZE_BYTES:
                files.append(path)
    return files


def discover_indicators(scan_root: Path, *, excluded_paths: set[Path] | None = None) -> list[IndicatorCandidate]:
    """Extract public IPs, domains and CIDRs without following repository symlinks.

    CIDRs remain intact; providers without range support report a lookup error.
    Binary files, large files, generated outputs and common build directories are skipped.
    """
    root = scan_root.resolve()
    workspace = Path.cwd().resolve()
    location_root = workspace if root.is_relative_to(workspace) else root
    exclusions = {path.resolve() for path in excluded_paths or set()}
    hits: dict[tuple[str, str], list[IndicatorHit]] = {}
    for file_path in _iter_files(root, exclusions):
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if "\0" in content:
            continue
        relative = file_path.relative_to(location_root).as_posix()
        for line_no, line in enumerate(content.splitlines(), start=1):
            values = set(IP_PATTERN.findall(line)) | set(IPV6_PATTERN.findall(line)) | set(DOMAIN_PATTERN.findall(line))
            for token in sorted(values):
                value = sanitize_indicator_value(token)
                if not should_scan_indicator(value):
                    continue
                kind = _indicator_kind(value)
                if kind == "ip":
                    value = str(ipaddress.ip_address(value))
                elif kind == "cidr":
                    value = str(ipaddress.ip_network(value, strict=False))
                hit = IndicatorHit(value, kind, relative, line_no)
                locations = hits.setdefault((value, kind), [])
                if hit not in locations:
                    locations.append(hit)
    return [
        IndicatorCandidate(value, kind, tuple(sorted(locations, key=lambda hit: (hit.file_path, hit.line))))
        for (value, kind), locations in sorted(hits.items())
    ]
