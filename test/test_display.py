"""Tests for ghsec.display module."""

from io import StringIO

from rich.console import Console

from ghsec.display import (
    _extract_description,
    _extract_severity,
    _severity_label,
    print_alert_detail,
    print_alerts_table,
)
from test.fixtures import (
    CODE_ALERT,
    CODE_ALERT_MINIMAL,
    DEP_ALERT,
    DEP_ALERT_NO_PATCH,
    SECRET_ALERT,
    SECRET_ALERT_MINIMAL,
)


def _capture(fn, *args, **kwargs) -> str:
    """Capture rich console output as plain text."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=120)
    # Temporarily replace the module-level console
    import ghsec.display as mod
    orig = mod.console
    mod.console = console
    try:
        fn(*args, **kwargs)
    finally:
        mod.console = orig
    return buf.getvalue()


# --- _severity_label ---


class TestSeverityLabel:
    def test_none(self):
        assert _severity_label(None) == "-"

    def test_empty_string(self):
        assert _severity_label("") == "-"

    def test_known_severity(self):
        label = _severity_label("critical")
        assert "critical" in label

    def test_unknown_severity(self):
        assert _severity_label("unknown") == "unknown"


# --- _extract_severity ---


class TestExtractSeverity:
    def test_code_with_security_level(self):
        assert _extract_severity(CODE_ALERT, "code") == "high"

    def test_code_fallback_to_severity(self):
        alert = {"rule": {"severity": "warning"}}
        assert _extract_severity(alert, "code") == "warning"

    def test_code_empty_rule(self):
        assert _extract_severity({"rule": {}}, "code") is None

    def test_dep(self):
        assert _extract_severity(DEP_ALERT, "dep") == "critical"

    def test_dep_fallback_advisory(self):
        alert = {"security_advisory": {"severity": "medium"}}
        assert _extract_severity(alert, "dep") == "medium"

    def test_secret_returns_none(self):
        assert _extract_severity(SECRET_ALERT, "secret") is None

    def test_empty_alert(self):
        assert _extract_severity({}, "code") is None


# --- _extract_description ---


class TestExtractDescription:
    def test_code(self):
        assert _extract_description(CODE_ALERT, "code") == "SQL query built from user-controlled sources"

    def test_code_fallback_to_id(self):
        assert _extract_description(CODE_ALERT_MINIMAL, "code") == "py/unused-import"

    def test_dep(self):
        assert _extract_description(DEP_ALERT, "dep") == "Remote code execution in lodash"

    def test_secret(self):
        assert _extract_description(SECRET_ALERT, "secret") == "GitHub Personal Access Token"

    def test_secret_fallback(self):
        assert _extract_description(SECRET_ALERT_MINIMAL, "secret") == "custom_secret"

    def test_empty_alert(self):
        assert _extract_description({}, "code") == ""


# --- print_alerts_table ---


class TestPrintAlertsTable:
    def test_empty_list(self):
        output = _capture(print_alerts_table, [], "code")
        assert "No alerts found" in output

    def test_code_alerts(self):
        output = _capture(print_alerts_table, [CODE_ALERT, CODE_ALERT_MINIMAL], "code")
        assert "1" in output
        assert "2" in output
        assert "SQL query" in output
        assert "open" in output

    def test_dep_alerts(self):
        output = _capture(print_alerts_table, [DEP_ALERT], "dep")
        assert "5" in output
        assert "lodash" in output

    def test_secret_alerts(self):
        output = _capture(print_alerts_table, [SECRET_ALERT], "secret")
        assert "3" in output
        assert "GitHub Personal Access Token" in output


# --- print_alert_detail ---


class TestPrintAlertDetail:
    def test_code_detail(self):
        output = _capture(print_alert_detail, CODE_ALERT, "code")
        assert "py/sql-injection" in output
        assert "CodeQL" in output
        assert "src/app/db.py:42" in output
        assert "high" in output

    def test_code_minimal(self):
        output = _capture(print_alert_detail, CODE_ALERT_MINIMAL, "code")
        assert "py/unused-import" in output

    def test_dep_detail(self):
        output = _capture(print_alert_detail, DEP_ALERT, "dep")
        assert "CVE-2025-1234" in output
        assert "9.8" in output
        assert "npm:lodash" in output
        assert "4.17.21" in output

    def test_dep_detail_no_patched_version(self):
        output = _capture(print_alert_detail, DEP_ALERT_NO_PATCH, "dep")
        assert "pip:diskcache" in output
        assert "<= 5.6.3" in output
        # Should not crash when first_patched_version is None
        assert "Patched Version" not in output

    def test_secret_detail(self):
        output = _capture(print_alert_detail, SECRET_ALERT, "secret")
        assert "GitHub Personal Access Token" in output
        assert "active" in output
        assert "False" in output  # publicly_leaked
        assert "True" in output   # push_protection_bypassed

    def test_secret_minimal(self):
        output = _capture(print_alert_detail, SECRET_ALERT_MINIMAL, "secret")
        assert "custom_secret" in output
