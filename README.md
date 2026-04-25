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
- Repository scanning mode (`--scan-path`) to auto-discover IPs, domains, and CIDRs
- SARIF export (`--sarif-file`) for GitHub Code Scanning and PR annotations
- Works as a Docker-based GitHub Action
- Clean, pluggable design with tests

## 🔧 Usage (CLI)

```bash
poetry run reputation-check <target> --source <source> [--api-key YOUR_KEY] [--output-file output.json]

# Scan a repository and emit SARIF for PR code scanning
poetry run reputation-check --source virustotal --api-key "$VT_API_KEY" --scan-path . --sarif-file results.sarif
```

### CLI Parameters
- `target` (required unless `--scan-path` is used): The IP, domain, or CIDR block to check.
- `--source` (required): The source to use for the reputation check (e.g., `virustotal`, `urlscan`).
- `--api-key` (optional): The API key for the selected source. Can also be set via environment variables (`VT_API_KEY` for VirusTotal, `URLSCAN_API_KEY` for urlscan.io).
- `--output-file` (optional): Path to save the raw JSON result.
- `--scan-path` (optional): Recursively scan a codebase for public indicators and check each one (filters private/reserved IP space and local/internal domains like `.local`/`.internal`).
- `--sarif-file` (optional): Path to save SARIF output for GitHub code scanning/PR annotations.
> Security note: scan mode normalizes extracted tokens, skips large files, and escapes workflow annotations to prevent CRLF/workflow-command injection issues.

## 🚀 Usage (GitHub Actions)

```yaml
- name: Run Network Reputation Check
  uses: ig596/network-reputation-check-action@main
  with:
    source: "virustotal"
    api-key: "${{ secrets.VT_API_KEY }}"
    scan-path: "."
    sarif-file: "network-reputation.sarif"

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: "network-reputation.sarif"
```

### GitHub Action Parameters
- `target` (required unless `--scan-path` is used): The IP, domain, or CIDR block to check.
- `source` (required): The source to use for the reputation check (e.g., `virustotal`, `urlscan`).
- `api-key` (optional): The API key for the selected source. Can be passed via GitHub Secrets.
- `scan-path` (optional): Recursively scan a repository path and evaluate all discovered indicators.
- `sarif-file` (optional): Write SARIF with file/line locations so PR/code-scanning annotations show where indicators were found.
- `output-file` (optional): Write raw JSON with per-indicator findings.

## 📦 Supported Sources
- VirusTotal
- urlscan.io

## 🔑 API Keys
- VirusTotal: `VT_API_KEY` (required)
- urlscan.io: `URLSCAN_API_KEY` (optional for most API calls)

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
