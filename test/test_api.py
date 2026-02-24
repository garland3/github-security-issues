"""Tests for ghsec.api module."""

import json
import subprocess
from unittest.mock import patch

import pytest

from ghsec.api import APIError, detect_repo, get_alert, gh_api, list_alerts, update_alert


# --- gh_api ---


def _mock_run(stdout="", returncode=0, stderr=""):
    """Create a mock for subprocess.run."""
    def side_effect(cmd, **kwargs):
        if returncode != 0:
            raise subprocess.CalledProcessError(returncode, cmd, output=stdout, stderr=stderr)
        result = subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)
        return result
    return side_effect


class TestGhApi:
    @patch("ghsec.api.subprocess.run")
    def test_get_request(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout='[{"number": 1}]', stderr="")
        result = gh_api("/repos/owner/repo/code-scanning/alerts")
        assert result == [{"number": 1}]
        cmd = mock_run.call_args[0][0]
        assert cmd == ["gh", "api", "/repos/owner/repo/code-scanning/alerts", "--method", "GET"]

    @patch("ghsec.api.subprocess.run")
    def test_patch_with_fields(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout='{"state": "dismissed"}', stderr="")
        result = gh_api("/repos/o/r/alerts/1", method="PATCH", fields={"state": "dismissed", "reason": "wont_fix"})
        assert result == {"state": "dismissed"}
        cmd = mock_run.call_args[0][0]
        assert "--method" in cmd
        assert "PATCH" in cmd
        assert "-f" in cmd
        assert "state=dismissed" in cmd
        assert "reason=wont_fix" in cmd

    @patch("ghsec.api.subprocess.run")
    def test_empty_response(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        assert gh_api("/repos/o/r/alerts") == {}

    @patch("ghsec.api.subprocess.run")
    def test_whitespace_response(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="  \n  ", stderr="")
        assert gh_api("/repos/o/r/alerts") == {}

    @patch("ghsec.api.subprocess.run", side_effect=FileNotFoundError)
    def test_gh_not_installed(self, mock_run):
        with pytest.raises(SystemExit):
            gh_api("/repos/o/r/alerts")

    @patch("ghsec.api.subprocess.run")
    def test_404_raises_api_error(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(4, "gh", stderr="gh: Not Found (HTTP 404)")
        with pytest.raises(APIError, match="Not found"):
            gh_api("/repos/o/r/alerts")

    @patch("ghsec.api.subprocess.run")
    def test_other_error_raises_api_error(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "gh", stderr="gh: some error")
        with pytest.raises(APIError, match="some error"):
            gh_api("/repos/o/r/alerts")

    @patch("ghsec.api.subprocess.run")
    def test_error_empty_stderr(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "gh", stderr="")
        with pytest.raises(APIError, match="exit code 1"):
            gh_api("/repos/o/r/alerts")


# --- detect_repo ---


class TestDetectRepo:
    @patch("ghsec.api.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, stdout="owner/repo\n", stderr="")
        assert detect_repo() == "owner/repo"

    @patch("ghsec.api.subprocess.run", side_effect=FileNotFoundError)
    def test_gh_not_found(self, mock_run):
        with pytest.raises(SystemExit):
            detect_repo()

    @patch("ghsec.api.subprocess.run")
    def test_command_fails(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "gh", stderr="not a git repo")
        with pytest.raises(SystemExit):
            detect_repo()


# --- list_alerts ---


class TestListAlerts:
    @patch("ghsec.api.gh_api")
    def test_basic_call(self, mock_gh):
        mock_gh.return_value = [{"number": 1}]
        result = list_alerts("owner/repo", "code")
        mock_gh.assert_called_once_with("/repos/owner/repo/code-scanning/alerts?per_page=100")
        assert result == [{"number": 1}]

    @patch("ghsec.api.gh_api")
    def test_with_state_filter(self, mock_gh):
        mock_gh.return_value = []
        list_alerts("owner/repo", "dep", state="open")
        endpoint = mock_gh.call_args[0][0]
        assert "state=open" in endpoint

    @patch("ghsec.api.gh_api")
    def test_with_severity_filter(self, mock_gh):
        mock_gh.return_value = []
        list_alerts("owner/repo", "secret", severity="critical")
        endpoint = mock_gh.call_args[0][0]
        assert "severity=critical" in endpoint

    @patch("ghsec.api.gh_api")
    def test_with_both_filters(self, mock_gh):
        mock_gh.return_value = []
        list_alerts("owner/repo", "code", state="dismissed", severity="high")
        endpoint = mock_gh.call_args[0][0]
        assert "state=dismissed" in endpoint
        assert "severity=high" in endpoint

    @patch("ghsec.api.gh_api")
    def test_all_alert_types(self, mock_gh):
        mock_gh.return_value = []
        for atype, path in [("code", "code-scanning"), ("dep", "dependabot"), ("secret", "secret-scanning")]:
            list_alerts("o/r", atype)
            endpoint = mock_gh.call_args[0][0]
            assert path in endpoint


# --- get_alert / update_alert ---


class TestGetAlert:
    @patch("ghsec.api.gh_api")
    def test_get(self, mock_gh):
        mock_gh.return_value = {"number": 42}
        result = get_alert("owner/repo", "code", 42)
        mock_gh.assert_called_once_with("/repos/owner/repo/code-scanning/alerts/42")
        assert result["number"] == 42


class TestUpdateAlert:
    @patch("ghsec.api.gh_api")
    def test_patch(self, mock_gh):
        mock_gh.return_value = {"state": "dismissed"}
        fields = {"state": "dismissed", "dismissed_reason": "wont_fix"}
        result = update_alert("owner/repo", "dep", 5, fields)
        mock_gh.assert_called_once_with(
            "/repos/owner/repo/dependabot/alerts/5", method="PATCH", fields=fields
        )
        assert result["state"] == "dismissed"
