"""GitHub API wrapper using the gh CLI."""

import json
import subprocess
import sys


def gh_api(endpoint: str, method: str = "GET", fields: dict | None = None) -> dict | list:
    """Call gh api and return parsed JSON."""
    cmd = ["gh", "api", endpoint, "--method", method]
    if fields:
        for key, value in fields.items():
            cmd.extend(["-f", f"{key}={value}"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("Error: 'gh' CLI not found. Install it from https://cli.github.com/", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip()
        if e.returncode == 4:
            # gh returns 4 for 404 — usually means feature not enabled
            raise APIError(f"Not found (HTTP 404). Is this feature enabled for the repo?\n{stderr}")
        raise APIError(stderr or f"gh api failed with exit code {e.returncode}")
    if not result.stdout.strip():
        return {}
    return json.loads(result.stdout)


class APIError(Exception):
    pass


def detect_repo() -> str:
    """Detect OWNER/REPO from the current git directory using gh."""
    try:
        result = subprocess.run(
            ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("Error: could not detect repo. Use --repo OWNER/REPO or run from inside a git repo.", file=sys.stderr)
        sys.exit(1)


# Maps our short type names to API path segments
ALERT_TYPE_PATHS = {
    "code": "code-scanning/alerts",
    "dep": "dependabot/alerts",
    "secret": "secret-scanning/alerts",
}


def list_alerts(repo: str, alert_type: str, state: str | None = None, severity: str | None = None) -> list:
    """Fetch alerts of the given type."""
    path = ALERT_TYPE_PATHS[alert_type]
    endpoint = f"/repos/{repo}/{path}?per_page=100"
    if state:
        endpoint += f"&state={state}"
    if severity:
        endpoint += f"&severity={severity}"
    return gh_api(endpoint)


def get_alert(repo: str, alert_type: str, alert_id: int) -> dict:
    """Fetch a single alert by ID."""
    path = ALERT_TYPE_PATHS[alert_type]
    return gh_api(f"/repos/{repo}/{path}/{alert_id}")


def update_alert(repo: str, alert_type: str, alert_id: int, fields: dict) -> dict:
    """PATCH a single alert (dismiss/reopen)."""
    path = ALERT_TYPE_PATHS[alert_type]
    return gh_api(f"/repos/{repo}/{path}/{alert_id}", method="PATCH", fields=fields)
