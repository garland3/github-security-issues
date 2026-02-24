"""Tests for ghsec.cli module."""

import json
from unittest.mock import patch

import pytest

from ghsec.api import APIError
from ghsec.cli import build_parser, main
from test.fixtures import CODE_ALERT, DEP_ALERT, SECRET_ALERT


# --- Argument parsing ---


class TestParser:
    def setup_method(self):
        self.parser = build_parser()

    def test_list_defaults(self):
        args = self.parser.parse_args(["list"])
        assert args.command == "list"
        assert args.state is None
        assert args.severity is None

    def test_list_with_filters(self):
        args = self.parser.parse_args(["list-code", "--state", "open", "--severity", "high"])
        assert args.command == "list-code"
        assert args.state == "open"
        assert args.severity == "high"

    def test_show_args(self):
        args = self.parser.parse_args(["show", "dep", "42"])
        assert args.command == "show"
        assert args.type == "dep"
        assert args.id == 42

    def test_dismiss_args(self):
        args = self.parser.parse_args(["dismiss", "code", "1", "--reason", "wont_fix", "--comment", "not relevant"])
        assert args.type == "code"
        assert args.id == 1
        assert args.reason == "wont_fix"
        assert args.comment == "not relevant"

    def test_dismiss_requires_reason(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args(["dismiss", "code", "1"])

    def test_reopen_args(self):
        args = self.parser.parse_args(["reopen", "secret", "7"])
        assert args.type == "secret"
        assert args.id == 7

    def test_global_repo_flag(self):
        args = self.parser.parse_args(["--repo", "owner/repo", "list"])
        assert args.repo == "owner/repo"

    def test_global_json_flag(self):
        args = self.parser.parse_args(["--json", "list-deps"])
        assert args.json is True

    def test_invalid_type_rejected(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args(["show", "invalid", "1"])

    def test_invalid_state_rejected(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args(["list", "--state", "bogus"])


# --- Command handlers ---


class TestCmdList:
    @patch("ghsec.cli.list_alerts")
    @patch("ghsec.cli.print_alerts_table")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_list_all(self, mock_detect, mock_table, mock_api):
        mock_api.return_value = [CODE_ALERT]
        parser = build_parser()
        args = parser.parse_args(["list"])
        args.func(args)
        # Should call list_alerts for all 3 types
        assert mock_api.call_count == 3
        assert mock_table.call_count == 3

    @patch("ghsec.cli.list_alerts")
    @patch("ghsec.cli.print_alerts_table")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_list_code_only(self, mock_detect, mock_table, mock_api):
        mock_api.return_value = [CODE_ALERT]
        parser = build_parser()
        args = parser.parse_args(["list-code"])
        args.func(args)
        assert mock_api.call_count == 1
        mock_api.assert_called_once_with("owner/repo", "code", state=None, severity=None)

    @patch("ghsec.cli.list_alerts")
    @patch("ghsec.cli.print_json")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_json_output(self, mock_detect, mock_json, mock_api):
        mock_api.return_value = [DEP_ALERT]
        parser = build_parser()
        args = parser.parse_args(["--json", "list-deps"])
        args.func(args)
        mock_json.assert_called_once_with([DEP_ALERT])

    @patch("ghsec.cli.list_alerts", side_effect=APIError("not found"))
    @patch("ghsec.cli.print_error")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_api_error_continues(self, mock_detect, mock_err, mock_api):
        parser = build_parser()
        args = parser.parse_args(["list"])
        args.func(args)  # should not raise
        assert mock_err.call_count == 3  # one error per type

    @patch("ghsec.cli.list_alerts")
    @patch("ghsec.cli.print_alerts_table")
    def test_explicit_repo(self, mock_table, mock_api):
        mock_api.return_value = []
        parser = build_parser()
        args = parser.parse_args(["--repo", "other/repo", "list-secrets"])
        args.func(args)
        mock_api.assert_called_once_with("other/repo", "secret", state=None, severity=None)

    @patch("ghsec.cli.list_alerts")
    @patch("ghsec.cli.print_alerts_table")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_filters_passed(self, mock_detect, mock_table, mock_api):
        mock_api.return_value = []
        parser = build_parser()
        args = parser.parse_args(["list-code", "--state", "dismissed", "--severity", "critical"])
        args.func(args)
        mock_api.assert_called_once_with("owner/repo", "code", state="dismissed", severity="critical")


class TestCmdShow:
    @patch("ghsec.cli.get_alert", return_value=CODE_ALERT)
    @patch("ghsec.cli.print_alert_detail")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_show_formatted(self, mock_detect, mock_detail, mock_api):
        parser = build_parser()
        args = parser.parse_args(["show", "code", "1"])
        args.func(args)
        mock_api.assert_called_once_with("owner/repo", "code", 1)
        mock_detail.assert_called_once_with(CODE_ALERT, "code")

    @patch("ghsec.cli.get_alert", return_value=DEP_ALERT)
    @patch("ghsec.cli.print_json")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_show_json(self, mock_detect, mock_json, mock_api):
        parser = build_parser()
        args = parser.parse_args(["--json", "show", "dep", "5"])
        args.func(args)
        mock_json.assert_called_once_with(DEP_ALERT)

    @patch("ghsec.cli.get_alert", side_effect=APIError("not found"))
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_show_error(self, mock_detect, mock_api):
        parser = build_parser()
        args = parser.parse_args(["show", "code", "999"])
        with pytest.raises(SystemExit):
            args.func(args)


class TestCmdDismiss:
    @patch("ghsec.cli.update_alert", return_value={})
    @patch("ghsec.cli.print_success")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_dismiss_code(self, mock_detect, mock_success, mock_update):
        parser = build_parser()
        args = parser.parse_args(["dismiss", "code", "1", "--reason", "wont_fix"])
        args.func(args)
        mock_update.assert_called_once_with("owner/repo", "code", 1, {
            "state": "dismissed",
            "dismissed_reason": "wont_fix",
        })
        mock_success.assert_called_once()

    @patch("ghsec.cli.update_alert", return_value={})
    @patch("ghsec.cli.print_success")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_dismiss_with_comment(self, mock_detect, mock_success, mock_update):
        parser = build_parser()
        args = parser.parse_args(["dismiss", "dep", "5", "--reason", "tolerable_risk", "--comment", "low priority"])
        args.func(args)
        fields = mock_update.call_args[0][3]
        assert fields["dismissed_comment"] == "low priority"

    @patch("ghsec.cli.update_alert", return_value={})
    @patch("ghsec.cli.print_success")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_dismiss_secret_uses_resolution_fields(self, mock_detect, mock_success, mock_update):
        parser = build_parser()
        args = parser.parse_args(["dismiss", "secret", "3", "--reason", "revoked", "--comment", "rotated key"])
        args.func(args)
        fields = mock_update.call_args[0][3]
        assert fields["state"] == "resolved"
        assert fields["resolution"] == "revoked"
        assert fields["resolution_comment"] == "rotated key"

    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_invalid_reason(self, mock_detect):
        parser = build_parser()
        args = parser.parse_args(["dismiss", "code", "1", "--reason", "bad_reason"])
        with pytest.raises(SystemExit):
            args.func(args)

    @patch("ghsec.cli.update_alert", side_effect=APIError("forbidden"))
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_dismiss_api_error(self, mock_detect, mock_update):
        parser = build_parser()
        args = parser.parse_args(["dismiss", "code", "1", "--reason", "wont_fix"])
        with pytest.raises(SystemExit):
            args.func(args)


class TestCmdReopen:
    @patch("ghsec.cli.update_alert", return_value={})
    @patch("ghsec.cli.print_success")
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_reopen(self, mock_detect, mock_success, mock_update):
        parser = build_parser()
        args = parser.parse_args(["reopen", "dep", "5"])
        args.func(args)
        mock_update.assert_called_once_with("owner/repo", "dep", 5, {"state": "open"})
        mock_success.assert_called_once()

    @patch("ghsec.cli.update_alert", side_effect=APIError("not found"))
    @patch("ghsec.cli.detect_repo", return_value="owner/repo")
    def test_reopen_error(self, mock_detect, mock_update):
        parser = build_parser()
        args = parser.parse_args(["reopen", "code", "99"])
        with pytest.raises(SystemExit):
            args.func(args)


# --- main() ---


class TestMain:
    @patch("sys.argv", ["ghsec"])
    def test_no_command_exits(self):
        with pytest.raises(SystemExit):
            main()
