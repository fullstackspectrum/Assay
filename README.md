# Cloudsmith Repository Vulnerability Overview

A CLI tool that fetches vulnerability scan data from the [Cloudsmith API](https://help.cloudsmith.io/reference) and produces a per-repository summary report — either as a Rich table in the terminal or as machine-readable JSON.

## Features

- Paginated fetching of all vulnerability scans for a repository
- Per-package severity breakdown (Critical, High, Medium, Low)
- Sorted output by total vulnerability count (descending)
- Rich terminal UI with progress bars, spinners, and color-coded output
- Clean JSON output mode (all status messages go to stderr)
- `--vulnerable-only` filter to hide clean packages

## Requirements

- Python 3.10+
- A valid [Cloudsmith API key](https://help.cloudsmith.io/reference/api-authentication)

## Installation

```bash
uv venv
uv pip install requests rich
```

## Configuration

Set your Cloudsmith API key as an environment variable:

```bash
export CLOUDSMITH_API_KEY="your-api-key-here"
```

## Usage

### Basic table output

```bash
python repo-vuln-summary.py --owner <org-slug> --repo <repo-slug>
```

### Only show vulnerable packages

```bash
python repo-vuln-summary.py --owner <org-slug> --repo <repo-slug> --vulnerable-only
```

### JSON output

```bash
python repo-vuln-summary.py --owner <org-slug> --repo <repo-slug> --output json
```

JSON output is written to stdout with all progress/status messages on stderr, so it is safe to pipe:

```bash
python repo-vuln-summary.py --owner <org-slug> --repo <repo-slug> --output json | jq .
```

## Arguments

| Argument | Required | Default | Description |
| --- | --- | --- | --- |
| `--owner` | Yes | | Organization/owner slug on Cloudsmith |
| `--repo` | Yes | | Repository slug on Cloudsmith |
| `--vulnerable-only` | No | `false` | Only include packages with vulnerabilities |
| `--output` | No | `table` | Output format: `table` or `json` |

## Example output

### Table

```
⬡ Cloudsmith Repository Vulnerability Overview
  Owner: my-org  Repo: my-repo

  ✓ Found 42 packages
  ! 7 packages have vulnerabilities

  ✓ Processed 7 vulnerability scans in 4.2s

              Cloudsmith Repository Vulnerability Overview: my-repo
┏━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━┳━━━━━━┳━━━━━┳━━━━━┓
┃ Package     ┃ Version ┃ Status           ┃ Total ┃ Crit ┃ High ┃ Med ┃ Low ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━╇━━━━━━╇━━━━━╇━━━━━┩
│ openssl     │ 3.5.2   │ VULNERABLE       │     5 │    1 │    2 │   2 │   0 │
│ libcrypto3  │ 3.5.2   │ VULNERABLE       │     3 │    0 │    0 │   2 │   1 │
│ curl        │ 8.5.0   │ VULNERABLE       │     1 │    0 │    1 │   0 │   0 │
│ zlib        │ 1.3.1   │ No issues found  │     0 │    0 │    0 │   0 │   0 │
└─────────────┴─────────┴──────────────────┴───────┴──────┴──────┴─────┴─────┘

  42 packages scanned, 3 vulnerable (1 critical, 3 high)
```

### JSON

```json
{
  "data": {
    "owner": "my-org",
    "repository": "my-repo",
    "packages": [
      {
        "package": "openssl",
        "version": "3.5.2",
        "slug_perm": "ABC123",
        "status": "vulnerable",
        "num_vulnerabilities": 5,
        "vulnerabilities": {
          "critical": 1,
          "high": 2,
          "medium": 2,
          "low": 0,
          "unknown": 0
        }
      }
    ]
  }
}
```

## API endpoints used

| Endpoint | Purpose |
| --- | --- |
| `GET /vulnerabilities/{owner}/{repo}/` | List all vulnerability scans (paginated) |
| `GET /v1/vulnerabilities/{owner}/{repo}/{package_slug}/{scan_id}/` | Fetch scan detail with severity breakdown via `scans[].results[]` |

## License

Copyright 2026 Cloudsmith Ltd