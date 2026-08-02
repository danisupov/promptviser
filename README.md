# promptviser

LLM Prompt Adviser for policy and safety scanning of prompt assets.

promptviser evaluates prompt files and emits findings that can be consumed in local workflows and CI/CD pipelines (including SARIF for GitHub Code Scanning).

## Table of contents

- Overview
- Architecture and 4-pass process
- Build and binaries
- Command reference
- Configuration reference
- Local quick start
- CI/CD integration (GitHub Actions)
- SARIF integration details
- Remediation workflow
- Suggested README images/examples
- Troubleshooting

## Overview

promptviser scans prompt files (`.yaml`, `.yml`, `.txt`, `.md`) and combines multiple analysis passes before matching findings against server-side rules.

Primary outcomes:

- Human-readable summary output for local use
- JSON output for automation
- SARIF output for Code Scanning platforms
- Optional remediation suggestions for detected findings

## Architecture and 4-pass process

promptviser runs a multi-pass analysis pipeline:

1. Pass 1 (Static regex)
  - Pattern checks against prompt content.

2. Pass 2 (Metadata analysis)
  - YAML/metadata-derived policy flags.

3. Pass 3 (AST/context caller analysis)
  - Looks for source files that reference prompt files and analyzes context triggers.

4. Pass 4 (LLM scoring)
  - Uses configured LLM provider to score prompt dimensions.

After all passes, results are sent to the adviser service for rule matching.

## Build and binaries

Build:

```sh
make build
```

Generated binaries:

- `bin/promptviser` (server)
- `bin/promptviserctl` (CLI)

Tip: if you use `pvctl` locally, define an alias:

```sh
alias pvctl="$PWD/bin/promptviserctl"
```

## Command reference

The CLI entrypoint is `promptviserctl`.

Global flags (common):

- `--server` server URL
- `--cfg` config file
- `--http` force HTTP client path
- `--trusted-ca` CA certificate for TLS
- `--storage` local storage path override
- `--o json|yaml` output format

Main commands:

1. `scan <path>`
  - Scans a directory.
  - Useful flags:
    - `--sarif`
    - `--sarif-output <file>`
    - `--save`
    - `--remediate`
    - `-v`

2. `scan-list [path-filter]`
  - Lists saved scans.

3. `scan-view <scan-id> [-v]`
  - Shows a saved scan.

4. `scan-delete <scan-id>` or `scan-delete --project <substring>`
  - Deletes saved scans.

5. `scan-diff <scan-id-a> <scan-id-b> [-v]`
  - Compares two saved scans.

6. `scan-remediate <scan-id>`
  - Generates remediation suggestions from saved findings.

7. `rules [-v]`
  - Displays loaded rule catalog.

8. `stats [-n <limit>]`
  - Shows aggregated violation stats.

9. `version`
  - Prints remote server version.

10. `server`
   - Prints remote server status.

11. `submit <data>`
   - Submits raw data for remote analysis.

## Configuration reference

You can configure promptviser with YAML configs in `etc/dev`.

Recommended provider-backed configs (non-stub):

- Azure OpenAI: `etc/dev/promptviser-config.yaml`
  - Requires `AZURE_OPENAI_API_KEY`

- Gemini: `etc/dev/promptviser-config.gemini.yaml`
  - Requires `GEMINI_API_KEY`

- OpenAI: `etc/dev/promptviser-config.openai.yaml`
  - Requires `OPENAI_API_KEY`

Provider env variable resolution uses `${ENV_VAR_NAME}` values in config.

Example (Azure section in `etc/dev/promptviser-config.yaml`):

```yaml
llm:
  provider: azure
  model: gpt-4o
  base_url: https://secdi-ai-dev.openai.azure.com
  api_key: ${AZURE_OPENAI_API_KEY}
  api_version: "2024-06-01"
```

## Local quick start

1. Set config root:

```sh
export PROMPTVISER_CONFIG_DIR="$PWD/etc/dev"
```

2. Export provider key (example: Azure):

```sh
export AZURE_OPENAI_API_KEY="<your-key>"
```

3. Start prerequisites and server:

```sh
make folders gen_test_certs start-localstack start-sql
./bin/promptviser --cfg "$PWD/etc/dev/promptviser-config.yaml" --only-server wfe
```

4. Run scan with SARIF output:

```sh
./bin/promptviserctl scan /path/to/project \
  --http \
  --server https://localhost:7880 \
  --cfg "$PWD/etc/dev/promptviser-config.yaml" \
  --trusted-ca /tmp/promptviser/certs/trusty_root_ca.pem \
  --sarif \
  --sarif-output promptviser.sarif.json
```

## CI/CD integration (GitHub Actions)

Reference workflow: `.github/workflows/code-scanning.yml`

Pipeline flow:

1. Build tools and binaries
2. Start SQL/Redis/certs dependencies
3. Start promptviser server
4. Wait for `/healthz` readiness
5. Run `promptviserctl scan` with SARIF output
6. Upload SARIF to GitHub Code Scanning

Required secret for Azure config:

- `AZURE_OPENAI_API_KEY`

If you switch configs, provide matching secrets for that provider.

## SARIF integration details

Use scan flags:

- `--sarif`
- `--sarif-output promptviser.sarif.json`

In CI, upload with:

- `github/codeql-action/upload-sarif`

SARIF output is best for:

- PR code scanning alerts
- security gate visibility
- compliance reporting pipelines

## Remediation workflow

Two common patterns:

1. Inline remediation during scan:

```sh
./bin/promptviserctl scan /path/to/project --remediate ...
```

2. Remediate a saved scan later:

```sh
./bin/promptviserctl scan-remediate <scan-id> --cfg <provider-config>
```

Notes:

- Remediation quality depends on LLM provider/model.
- Keep SARIF focused on findings; keep large remediation text in separate outputs/reports.

## Suggested README images/examples

For final presentation quality, add screenshots for:

1. GitHub Action run summary
2. Code Scanning alerts list for a PR
3. One SARIF finding expanded in GitHub UI
4. Terminal run showing `scan`, `scan-list`, and `scan-diff`
5. Remediation output example

Recommended supporting examples to include:

- Small demo repo with 2-3 prompt files (one compliant, one intentionally risky)
- Before/after scan comparison using `scan-diff`
- Example secret setup screenshot for `AZURE_OPENAI_API_KEY`

## Should this split into multiple docs?

This README can stay comprehensive for a class/final submission.

If project scope grows, split into:

- `docs/architecture.md` (4-pass details)
- `docs/ci-cd.md` (workflow templates)
- `docs/configuration.md` (provider configs)
- `docs/remediation.md` (remediation strategy)

## Troubleshooting

### `llm/azure: no API key provided`

Check all of the following:

- Secret name exactly matches `AZURE_OPENAI_API_KEY`
- Workflow maps secret to env var with same name
- Run context has secret access (same-repo branch/push)

### Server readiness timeout in CI

Inspect `/tmp/promptviser/promptviser.log` output from workflow readiness step.

### SARIF uploads but no alerts shown

Check:

- upload-sarif step ran successfully
- results are in the expected repository/PR scope
- rule severities/locations are populated in SARIF
