"""Canned API responses for testing."""

CODE_ALERT = {
    "number": 1,
    "state": "open",
    "html_url": "https://github.com/owner/repo/security/code-scanning/1",
    "created_at": "2025-01-15T10:30:00Z",
    "rule": {
        "id": "py/sql-injection",
        "description": "SQL query built from user-controlled sources",
        "severity": "error",
        "security_severity_level": "high",
    },
    "tool": {"name": "CodeQL", "version": "2.15.0"},
    "most_recent_instance": {
        "location": {
            "path": "src/app/db.py",
            "start_line": 42,
        }
    },
}

CODE_ALERT_MINIMAL = {
    "number": 2,
    "state": "dismissed",
    "html_url": "https://github.com/owner/repo/security/code-scanning/2",
    "created_at": "2025-02-01T08:00:00Z",
    "rule": {"id": "py/unused-import"},
    "tool": {},
    "most_recent_instance": {},
}

DEP_ALERT = {
    "number": 5,
    "state": "open",
    "html_url": "https://github.com/owner/repo/security/dependabot/5",
    "created_at": "2025-01-20T14:00:00Z",
    "security_advisory": {
        "summary": "Remote code execution in lodash",
        "severity": "critical",
        "identifiers": [
            {"type": "CVE", "value": "CVE-2025-1234"},
            {"type": "GHSA", "value": "GHSA-xxxx-yyyy"},
        ],
        "cvss": {"score": 9.8},
    },
    "security_vulnerability": {
        "package": {"ecosystem": "npm", "name": "lodash"},
        "vulnerable_version_range": "< 4.17.21",
        "first_patched_version": {"identifier": "4.17.21"},
        "severity": "critical",
    },
    "dependency": {
        "package": {"ecosystem": "npm", "name": "lodash"},
    },
}

DEP_ALERT_NO_PATCH = {
    "number": 17,
    "state": "open",
    "html_url": "https://github.com/owner/repo/security/dependabot/17",
    "created_at": "2025-03-01T12:00:00Z",
    "security_advisory": {
        "summary": "Unsafe deserialization in diskcache",
        "severity": "medium",
        "identifiers": [
            {"type": "GHSA", "value": "GHSA-w8v5-vhqr-4h9v"},
            {"type": "CVE", "value": "CVE-2025-69872"},
        ],
        "cvss": {"score": 0.0},
    },
    "security_vulnerability": {
        "package": {"ecosystem": "pip", "name": "diskcache"},
        "vulnerable_version_range": "<= 5.6.3",
        "first_patched_version": None,
        "severity": "medium",
    },
}

SECRET_ALERT = {
    "number": 3,
    "state": "open",
    "html_url": "https://github.com/owner/repo/security/secret-scanning/3",
    "created_at": "2025-01-10T09:00:00Z",
    "secret_type": "github_personal_access_token",
    "secret_type_display_name": "GitHub Personal Access Token",
    "validity": "active",
    "publicly_leaked": False,
    "push_protection_bypassed": True,
}

SECRET_ALERT_MINIMAL = {
    "number": 4,
    "state": "resolved",
    "html_url": "https://github.com/owner/repo/security/secret-scanning/4",
    "created_at": "2025-01-12T11:00:00Z",
    "secret_type": "custom_secret",
}
