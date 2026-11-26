# Network Reputation Check Action

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/ig596/network_reputation_checks/ci.yaml)
![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/github/license/ig596/network_reputation_checks)
![Poetry](https://img.shields.io/badge/managed%20with-poetry-blue)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)

![Coverage](https://raw.githubusercontent.com/ig596/network_reputation_checks/main/coverage.svg)
![Code Style](https://img.shields.io/badge/code%20style-ruff-blue)
![GitHub Release](https://img.shields.io/github/v/release/ig596/network_reputation_checks)
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

Local installs require Python 3.11 or newer.

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
  uses: ig596/network_reputation_checks@main
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
- VirusTotal
- urlscan.io

## 🔑 API Keys
- VirusTotal: `VT_API_KEY` (required)
- urlscan.io: `URLSCAN_API_KEY` (optional for most API calls)

## Reports and releases

Terminal reports and GitHub Actions job summaries include VirusTotal analysis
statistics and malicious engine detections, or the first five urlscan matches.
GitHub Actions also receives a notice or error annotation for each completed check.
A malicious or suspicious VirusTotal result fails the command.

Each invocation uses one source. To query both providers, run separate jobs with a
`source: [virustotal, urlscan]` matrix and the appropriate API key for each job.

The release workflow uses Conventional Commits and `python-semantic-release` to
update the project version. Routine PRs should not manually bump `pyproject.toml`.

### Release provenance and SBOMs

New releases publish GitHub build provenance attestations for the Python wheel,
source distribution, and Docker archive. Attestations use GitHub Actions OIDC
and Sigstore; no separate signing key is required. This is the starting point
for SLSA Build Level 2, without a claim of Level 3 build isolation.

Each release also includes `sbom.spdx.json` (the source repository's dependency
inventory) and `sbom.docker.spdx.json` (packages discovered in the actual Docker
image, including OS and installed Python packages). The Docker SBOM has a signed
SBOM attestation bound to the downloaded Docker archive's digest. The source SBOM
is a repository inventory, not an inventory of a resolved Python installation.
Existing releases are not retroactively attested.

Download an artifact from a new release and verify its provenance with a recent
GitHub CLI:

```bash
gh attestation verify ./network_reputation_check-VERSION-py3-none-any.whl \
  --repo ig596/network_reputation_checks \
  --signer-workflow ig596/network_reputation_checks/.github/workflows/release.yaml
```

Replace `VERSION` with the release version. The same command accepts the Python
source distribution or Docker archive path. Verify the Docker SBOM attestation
against the archive using:

```bash
gh attestation verify ./network-reputation-check-docker-VERSION.tar.gz \
  --repo ig596/network_reputation_checks \
  --signer-workflow ig596/network_reputation_checks/.github/workflows/release.yaml \
  --predicate-type https://spdx.dev/Document/v2.3
```

Attestations identify the workflow and artifact digest; they do not certify the
absence of vulnerabilities. The GitHub Action builds `Dockerfile` at runtime,
so verifying a release archive does not verify a separate Actions runtime build.

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
