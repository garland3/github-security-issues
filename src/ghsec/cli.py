"""CLI entry point for ghsec."""

import argparse
import sys

from ghsec.api import APIError, detect_repo, get_alert, list_alerts, update_alert
from ghsec.display import (
    print_alert_detail,
    print_alerts_table,
    print_error,
    print_json,
    print_success,
)

ALERT_TYPES = ["code", "dep", "secret"]

DISMISS_REASONS = {
    "code": ["false_positive", "wont_fix", "used_in_tests"],
    "dep": ["fix_started", "inaccurate", "no_bandwidth", "not_used", "tolerable_risk"],
    "secret": ["false_positive", "wont_fix", "revoked", "used_in_tests"],
}

# API field names for dismissal differ per alert type
DISMISS_FIELD_MAP = {
    "code": ("state", "dismissed", "dismissed_reason", "dismissed_comment"),
    "dep": ("state", "dismissed", "dismissed_reason", "dismissed_comment"),
    "secret": ("state", "resolved", "resolution", "resolution_comment"),
}

REOPEN_FIELD_MAP = {
    "code": {"state": "open"},
    "dep": {"state": "open"},
    "secret": {"state": "open"},
}


def _resolve_repo(args: argparse.Namespace) -> str:
    return args.repo if args.repo else detect_repo()


def _handle_list(args: argparse.Namespace, alert_types: list[str]) -> None:
    repo = _resolve_repo(args)
    for atype in alert_types:
        try:
            alerts = list_alerts(repo, atype, state=args.state, severity=args.severity)
        except APIError as e:
            print_error(f"[{atype}] {e}")
            continue
        if args.json:
            print_json(alerts)
        else:
            if len(alert_types) > 1:
                from rich.console import Console
                Console().print(f"\n[bold underline]{atype.upper()} scanning alerts[/]")
            print_alerts_table(alerts, atype)


def cmd_list(args: argparse.Namespace) -> None:
    _handle_list(args, ALERT_TYPES)


def cmd_list_code(args: argparse.Namespace) -> None:
    _handle_list(args, ["code"])


def cmd_list_deps(args: argparse.Namespace) -> None:
    _handle_list(args, ["dep"])


def cmd_list_secrets(args: argparse.Namespace) -> None:
    _handle_list(args, ["secret"])


def cmd_show(args: argparse.Namespace) -> None:
    repo = _resolve_repo(args)
    try:
        alert = get_alert(repo, args.type, args.id)
    except APIError as e:
        print_error(str(e))
        sys.exit(1)
    if args.json:
        print_json(alert)
    else:
        print_alert_detail(alert, args.type)


def cmd_dismiss(args: argparse.Namespace) -> None:
    repo = _resolve_repo(args)
    atype = args.type
    valid = DISMISS_REASONS[atype]
    if args.reason not in valid:
        print_error(f"Invalid reason '{args.reason}' for {atype}. Valid: {', '.join(valid)}")
        sys.exit(1)

    state_field, state_val, reason_field, comment_field = DISMISS_FIELD_MAP[atype]
    fields = {state_field: state_val, reason_field: args.reason}
    if args.comment:
        fields[comment_field] = args.comment

    try:
        update_alert(repo, atype, args.id, fields)
    except APIError as e:
        print_error(str(e))
        sys.exit(1)
    print_success(f"Dismissed {atype} alert #{args.id}")


def cmd_reopen(args: argparse.Namespace) -> None:
    repo = _resolve_repo(args)
    try:
        update_alert(repo, args.type, args.id, REOPEN_FIELD_MAP[args.type])
    except APIError as e:
        print_error(str(e))
        sys.exit(1)
    print_success(f"Reopened {args.type} alert #{args.id}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ghsec", description="GitHub Security Alerts CLI")
    parser.add_argument("--repo", help="Override repo (OWNER/REPO). Default: auto-detect from git remote")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted tables")

    sub = parser.add_subparsers(dest="command")

    # Shared filter arguments
    def add_list_filters(p: argparse.ArgumentParser) -> None:
        p.add_argument("--state", choices=["open", "dismissed", "fixed"], default=None, help="Filter by state")
        p.add_argument("--severity", choices=["critical", "high", "medium", "low"], default=None, help="Filter by severity")

    p_list = sub.add_parser("list", help="List all security alerts")
    add_list_filters(p_list)
    p_list.set_defaults(func=cmd_list)

    p_code = sub.add_parser("list-code", help="List code scanning alerts")
    add_list_filters(p_code)
    p_code.set_defaults(func=cmd_list_code)

    p_deps = sub.add_parser("list-deps", help="List Dependabot alerts")
    add_list_filters(p_deps)
    p_deps.set_defaults(func=cmd_list_deps)

    p_secrets = sub.add_parser("list-secrets", help="List secret scanning alerts")
    add_list_filters(p_secrets)
    p_secrets.set_defaults(func=cmd_list_secrets)

    p_show = sub.add_parser("show", help="Show detail for one alert")
    p_show.add_argument("type", choices=ALERT_TYPES, help="Alert type")
    p_show.add_argument("id", type=int, help="Alert number")
    p_show.set_defaults(func=cmd_show)

    p_dismiss = sub.add_parser("dismiss", help="Dismiss an alert")
    p_dismiss.add_argument("type", choices=ALERT_TYPES, help="Alert type")
    p_dismiss.add_argument("id", type=int, help="Alert number")
    p_dismiss.add_argument("--reason", required=True, help="Dismissal reason")
    p_dismiss.add_argument("--comment", help="Optional comment")
    p_dismiss.set_defaults(func=cmd_dismiss)

    p_reopen = sub.add_parser("reopen", help="Reopen a dismissed alert")
    p_reopen.add_argument("type", choices=ALERT_TYPES, help="Alert type")
    p_reopen.add_argument("id", type=int, help="Alert number")
    p_reopen.set_defaults(func=cmd_reopen)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
