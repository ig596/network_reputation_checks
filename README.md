# Network Reputation Check Action

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/ig596/network-reputation-check-action/ci.yml?branch=main)
![Python Version](https://img.shields.io/badge/python-3.11-blue)
![License](https://img.shields.io/github/license/ig596/network-reputation-check-action)
![Poetry](https://img.shields.io/badge/managed%20with-poetry-blue)

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
- VirusTotal
- urlscan.io

## 🔑 API Keys
- VirusTotal: `VT_API_KEY`
- urlscan.io: `URLSCAN_API_KEY`

## 📜 License

This project is licensed under the [MIT License](LICENSE).
