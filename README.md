# ghsec — GitHub Security Alerts CLI

[![CI](https://github.com/garland3/github-security-issues/actions/workflows/ci.yml/badge.svg)](https://github.com/garland3/github-security-issues/actions/workflows/ci.yml)
[![Publish to PyPI](https://github.com/garland3/github-security-issues/actions/workflows/publish.yml/badge.svg)](https://github.com/garland3/github-security-issues/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/ghsec)](https://pypi.org/project/ghsec/)

A command-line tool that wraps the `gh` CLI to fetch, display, and manage GitHub security alerts (CodeQL/code scanning, Dependabot, secret scanning).

## Prerequisites

- Python >= 3.10
- [`gh` CLI](https://cli.github.com/) installed and authenticated (`gh auth login`)
- [`uv`](https://docs.astral.sh/uv/) for package management (recommended)

## Installation

```bash
uv pip install .
```

Or for development:

```bash
uv sync
```

## Usage

Run `ghsec` from inside a cloned GitHub repo (it auto-detects the repo from git remote), or specify `--repo OWNER/REPO`.

```
ghsec <subcommand> [options]

Global options:
  --repo OWNER/REPO    Override repo (default: auto-detect from git remote)
  --json               Output raw JSON instead of formatted tables
```

### List alerts

```bash
# All security alert types
ghsec list

# Specific types
ghsec list-code          # Code scanning (CodeQL) only
ghsec list-deps          # Dependabot only
ghsec list-secrets       # Secret scanning only

# Filter by state or severity
ghsec list-code --state open --severity high
```

### Show alert details

```bash
ghsec show code 1        # Code scanning alert #1
ghsec show dep 5         # Dependabot alert #5
ghsec show secret 3      # Secret scanning alert #3
```

### Dismiss an alert

```bash
# Code scanning reasons: false_positive, wont_fix, used_in_tests
ghsec dismiss code 1 --reason wont_fix

# Dependabot reasons: fix_started, inaccurate, no_bandwidth, not_used, tolerable_risk
ghsec dismiss dep 5 --reason tolerable_risk --comment "low priority"

# Secret scanning reasons: false_positive, wont_fix, revoked, used_in_tests
ghsec dismiss secret 3 --reason revoked
```

### Reopen a dismissed alert

```bash
ghsec reopen dep 5
```

### JSON output

```bash
ghsec --json list-deps
ghsec --json show code 1
```

## Running tests

```bash
bash test/run_tests.sh
```

## Project structure

```
├── pyproject.toml          # Package metadata, dependencies, entry point
├── src/
│   └── ghsec/
│       ├── __init__.py     # Version string
│       ├── cli.py          # argparse setup, main entry point
│       ├── api.py          # gh api wrapper functions
│       └── display.py      # Rich table/detail formatting
└── test/
    ├── run_tests.sh        # Test runner script
    ├── fixtures.py         # Canned API responses
    ├── test_api.py         # API module tests
    ├── test_display.py     # Display formatting tests
    └── test_cli.py         # CLI argument & command handler tests
```

## License

MIT
