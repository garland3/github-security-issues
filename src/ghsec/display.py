"""Rich formatting for security alert output."""

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
err_console = Console(stderr=True)


def print_json(data: dict | list) -> None:
    """Print raw JSON output."""
    console.print(json.dumps(data, indent=2))


def print_error(msg: str) -> None:
    err_console.print(f"[bold red]Error:[/] {msg}")


def print_success(msg: str) -> None:
    console.print(f"[bold green]OK:[/] {msg}")


SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}


def _severity_label(sev: str | None) -> str:
    if not sev:
        return "-"
    color = SEVERITY_COLORS.get(sev.lower(), "")
    return f"[{color}]{sev}[/]" if color else sev


def _extract_severity(alert: dict, alert_type: str) -> str | None:
    """Pull severity from the type-specific location in the alert JSON."""
    if alert_type == "code":
        rule = alert.get("rule", {})
        return rule.get("security_severity_level") or rule.get("severity")
    if alert_type == "dep":
        vuln = (alert.get("security_vulnerability") or alert.get("security_advisory", {}))
        return vuln.get("severity")
    return None  # secret scanning has no severity


def _extract_description(alert: dict, alert_type: str) -> str:
    """Pull a short description from the alert."""
    if alert_type == "code":
        rule = alert.get("rule", {})
        return rule.get("description", rule.get("id", ""))
    if alert_type == "dep":
        adv = alert.get("security_advisory", {})
        return adv.get("summary", alert.get("dependency", {}).get("package", {}).get("name", ""))
    if alert_type == "secret":
        return alert.get("secret_type_display_name", alert.get("secret_type", ""))
    return ""


def print_alerts_table(alerts: list, alert_type: str) -> None:
    """Render a rich table of alerts."""
    if not alerts:
        console.print("[dim]No alerts found.[/]")
        return

    table = Table(show_lines=False, pad_edge=True)
    table.add_column("#", style="bold cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Description")
    table.add_column("State", no_wrap=True)
    table.add_column("Created", no_wrap=True)

    for a in alerts:
        number = str(a.get("number", ""))
        sev = _severity_label(_extract_severity(a, alert_type))
        desc = _extract_description(a, alert_type)
        state = a.get("state", "")
        created = (a.get("created_at") or "")[:10]
        table.add_row(number, sev, desc, state, created)

    console.print(table)


def print_alert_detail(alert: dict, alert_type: str) -> None:
    """Render detailed info for a single alert."""
    rows: list[tuple[str, str]] = []

    rows.append(("Number", str(alert.get("number", ""))))
    rows.append(("State", alert.get("state", "")))
    rows.append(("URL", alert.get("html_url", "")))
    rows.append(("Created", alert.get("created_at", "")))

    if alert_type == "code":
        rule = alert.get("rule", {})
        rows.append(("Rule ID", rule.get("id", "")))
        rows.append(("Rule Description", rule.get("description", "")))
        rows.append(("Severity", rule.get("security_severity_level") or rule.get("severity", "")))
        tool = alert.get("tool", {})
        rows.append(("Tool", tool.get("name", "")))
        loc = alert.get("most_recent_instance", {}).get("location", {})
        if loc:
            path = loc.get("path", "")
            line = loc.get("start_line", "")
            rows.append(("Location", f"{path}:{line}" if line else path))

    elif alert_type == "dep":
        adv = alert.get("security_advisory", {})
        rows.append(("Advisory Summary", adv.get("summary", "")))
        rows.append(("Severity", adv.get("severity", "")))
        for cve in adv.get("identifiers", []):
            rows.append((cve.get("type", "ID"), cve.get("value", "")))
        cvss = adv.get("cvss", {})
        if cvss:
            rows.append(("CVSS Score", str(cvss.get("score", ""))))
        vuln = alert.get("security_vulnerability", {})
        pkg = vuln.get("package", {})
        rows.append(("Package", f"{pkg.get('ecosystem', '')}:{pkg.get('name', '')}"))
        rows.append(("Vulnerable Range", vuln.get("vulnerable_version_range", "")))
        rows.append(("Patched Version", vuln.get("first_patched_version", {}).get("identifier", "")))

    elif alert_type == "secret":
        rows.append(("Secret Type", alert.get("secret_type_display_name", alert.get("secret_type", ""))))
        rows.append(("Validity", alert.get("validity", "")))
        if alert.get("publicly_leaked") is not None:
            rows.append(("Publicly Leaked", str(alert["publicly_leaked"])))
        if alert.get("push_protection_bypassed") is not None:
            rows.append(("Push Protection Bypassed", str(alert["push_protection_bypassed"])))

    # Build rich panel content
    content = "\n".join(f"[bold]{k}:[/] {v}" for k, v in rows if v)
    console.print(Panel(content, title=f"Alert #{alert.get('number', '')}", expand=False))
