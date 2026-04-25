# Network Reputation Check Action

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/ig596/network-reputation-check-action/ci.yml?branch=main)
![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/github/license/ig596/network_reputation_checks)
![Poetry](https://img.shields.io/badge/managed%20with-poetry-blue)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)

![Coverage](./coverage.svg)
![Code Style](https://img.shields.io/badge/code%20style-ruff-blue)
![PyPI Version](https://img.shields.io/pypi/v/network_reputation_checks)
![Downloads](https://img.shields.io/pypi/dm/network-reputation-check)
![GitHub Stars](https://img.shields.io/github/stars/ig596/network_reputation_checks?style=social)
![GitHub Issues](https://img.shields.io/github/issues/ig596/network_reputation_checks)
![Last Commit](https://img.shields.io/github/last-commit/ig596/network_reputation_checks)

A GitHub Action and CLI tool to check the reputation of IPs, domains, or CIDR blocks using threat intelligence sources like VirusTotal and urlscan.io.

## ✅ Features
- Click-powered CLI
- Supports one source per run
- Works as a Docker-based GitHub Action
- Clean, pluggable design with tests

## 🔧 Usage (CLI)

```bash
poetry run reputation-check <target> --source <source> [--api-key YOUR_KEY] [--output-file output.json]
```

### CLI Parameters
- `target` (required): The IP, domain, or CIDR block to check.
- `--source` (required): The source to use for the reputation check (e.g., `virustotal`, `urlscan`).
- `--api-key` (optional): The API key for the selected source. Can also be set via environment variables (`VT_API_KEY` for VirusTotal, `URLSCAN_API_KEY` for urlscan.io).
- `--output-file` (optional): Path to save the raw JSON result.

## 🚀 Usage (GitHub Actions)

```yaml
- name: Run Network Reputation Check
  uses: ig596/network-reputation-check-action@main
  with:
    target: "example.com"
    source: "virustotal"
    api-key: "${{ secrets.VT_API_KEY }}"
```

### GitHub Action Parameters
- `target` (required): The IP, domain, or CIDR block to check.
- `source` (required): The source to use for the reputation check (e.g., `virustotal`, `urlscan`).
- `api-key` (optional): The API key for the selected source. Can be passed via GitHub Secrets.

## 📦 Supported Sources
- `virustotal`
  - Target types: domain, IPv4, IPv6
  - API key: required
- `urlscan`
  - Target types: domain
  - API key: required in this action implementation

> Note: The tool intentionally runs **one source per invocation** for simplicity and predictable failure behavior.

## 🔁 Running Multiple Sources (Recommended Matrix Pattern)

If you want to run both sources for the same target, use a GitHub Actions matrix so each source runs in an isolated job.

```yaml
jobs:
  reputation-check:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        source: [virustotal, urlscan]
    steps:
      - uses: actions/checkout@v6
      - name: Network Reputation Check (${{ matrix.source }})
        uses: ig596/network-reputation-check-action@main
        with:
          target: "example.com"
          source: ${{ matrix.source }}
          api-key: ${{ matrix.source == 'virustotal' && secrets.VT_API_KEY || secrets.URLSCAN_API_KEY }}
```

Why matrix is preferred:
- Simpler and safer than chaining multiple lookups in one step.
- Better observability (one check result per source).
- Parallel execution improves CI time.

## 🔑 API Keys
- VirusTotal: `VT_API_KEY` (required)
- urlscan.io: `URLSCAN_API_KEY` (optional for most API calls)

## 🏷️ Versioning & Releases

Project version bumps are handled automatically by the release workflow using Conventional Commits and `python-semantic-release`. In normal PRs, do **not** manually edit `pyproject.toml` just to bump the version; the release job creates `chore(release): x.y.z [skip ci]` commits on `main` when appropriate.

## 🔧 Development Setup

### Pre-commit Hooks

This project uses pre-commit hooks to enforce code quality. Install and activate them with:

```bash
pip install pre-commit
pre-commit install
```

You can manually run the hooks on all files with:
```bash
pre-commit run --all-files
```

## 📜 License
This project is licensed under the [MIT License](LICENSE).
