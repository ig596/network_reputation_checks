# Network Reputation Check

[![CI](https://img.shields.io/github/actions/workflow/status/ig596/network_reputation_checks/ci.yaml)](https://github.com/ig596/network_reputation_checks/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/ig596/network_reputation_checks)](https://github.com/ig596/network_reputation_checks/releases/latest)
![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue)
[![Coverage](https://raw.githubusercontent.com/ig596/network_reputation_checks/main/coverage.svg)](https://github.com/ig596/network_reputation_checks/blob/main/coverage.svg)
[![License](https://img.shields.io/github/license/ig596/network_reputation_checks)](LICENSE)

Network Reputation Check is a Docker-based GitHub Action and Python CLI for
looking up an IP address or domain with VirusTotal or urlscan.io. Each run
queries one provider and prints a human-readable report. In GitHub Actions, it
also writes the report to the job summary.

## GitHub Actions

```yaml
- name: Check domain reputation
  uses: ig596/network_reputation_checks@v1
  with:
    target: example.com
    source: virustotal
    api-key: ${{ secrets.VT_API_KEY }}
```

Use a separate step for each provider when both results are needed.

### Inputs

| Input | Required | Description |
| --- | --- | --- |
| `target` | Yes | IP address or domain to check. urlscan.io accepts domains only. |
| `source` | Yes | `virustotal` or `urlscan`. |
| `api-key` | Yes in practice | Provider API key. Both current provider implementations reject a missing key. |

CIDR ranges are not currently supported.

## CLI

The project requires Python 3.11 or newer and uses Poetry for local installs.
It is not currently published to the production Python Package Index.

```bash
git clone https://github.com/ig596/network_reputation_checks.git
cd network_reputation_checks
poetry install

poetry run reputation-check example.com \
  --source virustotal \
  --api-key "$VT_API_KEY" \
  --output-file result.json
```

The CLI also accepts the provider key through the `API_KEY` environment
variable:

```bash
API_KEY="$URLSCAN_API_KEY" poetry run reputation-check example.com --source urlscan
```

Run `poetry run reputation-check --help` for the complete command reference.

## Providers and results

| Provider | Targets | Reported result | Exit behavior |
| --- | --- | --- | --- |
| VirusTotal | IP addresses and domains | Analysis statistics and malicious engine detections | Exits with status 1 when VirusTotal reports a malicious or suspicious detection. |
| urlscan.io | Domains | Up to the first five matching scans | Exits with status 1 for request or API errors; matching scans do not currently fail the command. |

When the CLI runs inside GitHub Actions, both providers write Markdown to the
job summary. VirusTotal checks also emit a notice or error annotation.

## Release artifacts

Releases include a Python wheel, source distribution, Docker archive, and two
SPDX SBOMs:

- `sbom.spdx.json` inventories the source repository's dependencies.
- `sbom.docker.spdx.json` inventories packages in the built Docker image.

GitHub build-provenance attestations cover the Python distributions and Docker
archive. The Docker SBOM also has an attestation bound to the archive digest.
These attestations identify the build workflow and artifact digest; they do not
certify that an artifact is free of vulnerabilities.

Verify a downloaded release artifact with a recent GitHub CLI:

```bash
gh attestation verify ./network_reputation_check-VERSION-py3-none-any.whl \
  --repo ig596/network_reputation_checks \
  --signer-workflow ig596/network_reputation_checks/.github/workflows/release.yaml
```

Replace `VERSION` with the release version. The same command accepts the source
distribution or Docker archive. Releases use Conventional Commits and
`python-semantic-release`; routine pull requests should not edit the version in
`pyproject.toml` manually.

## Development

```bash
poetry install --with dev
poetry run pre-commit install
poetry run pre-commit run --all-files
poetry run pytest
```

## License

Licensed under the [MIT License](LICENSE).
