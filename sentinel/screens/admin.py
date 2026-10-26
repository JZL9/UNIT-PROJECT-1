from rich.panel import Panel
from rich.table import Table

from sentinel.case_store import find_case, load_cases, next_case_id, save_cases
from sentinel.correlation import open_campaigns
from sentinel.dashboard import build_stats
from sentinel.exporter import export_case, export_summary
from sentinel.models import Case
from sentinel.report_store import load_reports
from sentinel.screens.display import (
    STATUS_STYLES,
    THEME,
    ask_choice,
    ask_text,
    console,
    get_keys,
    show_menu,
    show_reports_table,
)

ADMIN_OPTIONS = [
    ("1", "📥 All Reports"),
    ("2", "📁 Cases"),
    ("3", "🔗 Correlation Alerts"),
    ("4", "📊 Dashboard"),
    ("5", "📄 Export Report"),
    ("0", "Logout"),
]

REPORT_FILTERS = [
    ("1", "All reports"),
    ("2", "High risk only"),
    ("3", "By user"),
    ("4", "By type"),
    ("0", "Back"),
]

CASE_OPTIONS = [
    ("1", "➕ New case"),
    ("2", "📋 List cases"),
    ("3", "🔎 Search cases"),
    ("4", "✏️  Edit case"),
    ("5", "🗑️  Delete case"),
    ("0", "Back"),
]

CASE_STATUS_COLORS = {
    "open": "red",
    "investigating": "yellow",
    "closed": "green",
}

EDIT_OPTIONS = [
    ("1", "Change title"),
    ("2", "Change status"),
    ("3", "Add note"),
    ("4", "Link a report"),
    ("5", "Unlink a report"),
    ("0", "Back"),
]

ALERT_ACTIONS = [
    ("1", "📁 Create a case from this alert"),
    ("2", "➕ Add to an existing case"),
    ("0", "Back"),
]

EXPORT_OPTIONS = [
    ("1", "📁 Export a case"),
    ("2", "📊 Export full summary"),
    ("0", "Back"),
]

BAR_WIDTH = 20


def filter_reports(reports):
    """Ask the admin how to filter. Return the filtered list, or None to go back."""
    show_menu("FILTER REPORTS", REPORT_FILTERS)
    choice = ask_choice("Choose: ", get_keys(REPORT_FILTERS))

    if choice == "0":
        return None
    if choice == "2":
        return list(filter(lambda report: report.is_dangerous(), reports))
    if choice == "3":
        user = input("User name: ").strip().title()
        return list(filter(lambda report: report.user == user, reports))
    if choice == "4":
        scan_type = ask_choice("Type (password / url): ", ["password", "url"])
        return list(filter(lambda report: report.scan_type == scan_type, reports))
    return reports


def ask_report_id(reports, prompt="Report ID for details (Enter to go back): "):
    """Ask for an ID from the shown reports. Return that Report, or None to go back."""
    ids = list(map(lambda report: str(report.report_id), reports))
    while True:
        answer = input(prompt).strip()
        if not answer:
            return None
        if answer in ids:
            return reports[ids.index(answer)]
        console.print(f"[red]❌ No report with ID {answer} in this list.[/red]")


def show_report_details(report):
    """Show every detail of one report inside a colored box."""
    color, label = STATUS_STYLES[report.status]
    lines = [
        f"{label}   Risk: {report.risk}/100",
        f"User:   {report.user}",
        f"Type:   {report.scan_type}",
        f"Target: {report.target}",
        f"Date:   {report.created_at}",
        "",
        report.summary,
    ]
    lines.extend(report.details)
    if report.indicators.get("ip"):
        lines.append(f"🧩 Indicator IP: {report.indicators['ip']}")
    console.print(Panel("\n".join(lines), title=f"Report #{report.report_id}", border_style=color))


def show_all_reports():
    """Admin view: list all users' reports with an optional filter."""
    reports = load_reports()
    if not reports:
        console.print("[yellow]No reports yet.[/yellow]")
        return

    filtered = filter_reports(reports)
    if filtered is None:
        return
    if not filtered:
        console.print("[yellow]No reports match this filter.[/yellow]")
        return

    show_reports_table(filtered, f"📥 REPORTS ({len(filtered)})", show_user=True)
    report = ask_report_id(filtered)
    if report:
        show_report_details(report)


# Cases
def show_cases_table(cases, reports):
    """Print a table of cases with their status and average risk."""
    table = Table(title=f"📁 CASES ({len(cases)})")
    table.add_column("#", justify="right")
    table.add_column("Title", overflow="fold")
    table.add_column("Status")
    table.add_column("Reports", justify="right")
    table.add_column("Avg Risk", justify="right")

    for case in cases:
        color = CASE_STATUS_COLORS[case.status]
        table.add_row(
            str(case.case_id),
            case.title,
            f"[{color}]{case.status}[/{color}]",
            str(len(case.report_ids)),
            str(case.average_risk(reports)),
        )

    console.print(table)


def create_case(cases):
    """Ask for a title and save a new case."""
    title = ask_text("Case title: ")
    case = Case(title=title, case_id=next_case_id(cases))
    cases.append(case)
    save_cases(cases)
    console.print(f"[green]✅ Case #{case.case_id} \"{case.title}\" created.[/green]")


def list_cases(cases):
    """Show all cases, or a message if there are none."""
    if not cases:
        console.print("[yellow]No cases yet. Create one with option 1.[/yellow]")
        return
    show_cases_table(cases, load_reports())


def ask_case(cases):
    """Show the cases and ask for an ID. Return the Case, or None to go back."""
    if not cases:
        console.print("[yellow]No cases yet. Create one with option 1.[/yellow]")
        return None

    show_cases_table(cases, load_reports())
    while True:
        answer = input("Case ID (Enter to go back): ").strip()
        if not answer:
            return None
        if answer.isdigit():
            case = find_case(cases, int(answer))
            if case:
                return case
        console.print(f"[red]❌ No case with ID {answer}.[/red]")


def show_case_details(case, reports):
    """Show the case info, its notes, and its linked reports."""
    color = CASE_STATUS_COLORS[case.status]
    lines = [
        f"Status:   [{color}]{case.status}[/{color}]",
        f"Created:  {case.created_at}",
        f"Avg risk: {case.average_risk(reports)}/100",
        "",
        "📝 Notes:",
    ]
    lines.extend(map(lambda note: f"  • {note}", case.notes or ["(no notes yet)"]))
    console.print(Panel("\n".join(lines), title=f"Case #{case.case_id} — {case.title}", border_style=color))

    linked = list(filter(lambda report: report.report_id in case.report_ids, reports))
    if linked:
        show_reports_table(linked, "🔗 Linked reports", show_user=True)
    else:
        console.print("[dim]No reports linked to this case yet.[/dim]")


def edit_case(cases):
    """Pick a case, then change its title, status, notes or linked reports."""
    case = ask_case(cases)
    if case is None:
        return

    reports = load_reports()
    while True:
        show_case_details(case, reports)
        show_menu(f"EDIT CASE #{case.case_id}", EDIT_OPTIONS)
        choice = ask_choice("Choose: ", get_keys(EDIT_OPTIONS))

        if choice == "0":
            return
        if choice == "1":
            case.title = ask_text("New title: ")
        elif choice == "2":
            status = ask_choice(f"New status ({' / '.join(Case.STATUSES)}): ", list(Case.STATUSES))
            case.set_status(status)
        elif choice == "3":
            case.add_note(ask_text("Note: "))
        elif choice == "4":
            show_reports_table(reports, "📥 ALL REPORTS", show_user=True)
            report = ask_report_id(reports, "Report ID to link (Enter to cancel): ")
            if report is None:
                continue
            if not case.add_report(report.report_id):
                console.print("[yellow]This report is already linked.[/yellow]")
                continue
        elif choice == "5":
            linked = list(filter(lambda r: r.report_id in case.report_ids, reports))
            if not linked:
                console.print("[yellow]No linked reports to remove.[/yellow]")
                continue
            report = ask_report_id(linked, "Report ID to unlink (Enter to cancel): ")
            if report is None:
                continue
            case.remove_report(report.report_id)

        save_cases(cases)
        console.print("[green]✅ Case updated.[/green]")


def case_matches(case, word):
    """True if the word appears in the case title or in any of its notes."""
    in_title = word in case.title.lower()
    in_notes = any(map(lambda note: word in note.lower(), case.notes))
    return in_title or in_notes


def search_cases(cases):
    """Show the cases whose title or notes contain a word."""
    if not cases:
        console.print("[yellow]No cases yet. Create one with option 1.[/yellow]")
        return

    word = ask_text("Search for: ", min_length=2).lower()
    found = list(filter(lambda case: case_matches(case, word), cases))
    if not found:
        console.print(f"[yellow]No cases match \"{word}\".[/yellow]")
        return
    show_cases_table(found, load_reports())


def delete_case(cases):
    """Pick a case and delete it after the admin confirms."""
    case = ask_case(cases)
    if case is None:
        return

    confirm = input(f"Type the case ID ({case.case_id}) to confirm deletion: ").strip()
    if confirm != str(case.case_id):
        console.print("[yellow]Deletion cancelled.[/yellow]")
        return

    cases.remove(case)
    save_cases(cases)
    console.print(f"[green]🗑️ Case #{case.case_id} deleted. Its reports are kept.[/green]")


#Dashboard
def draw_bar(value, max_value, color):
    """Return a colored bar like '██████' sized relative to the biggest value."""
    length = round(value / max_value * BAR_WIDTH) if max_value else 0
    return f"[{color}]{'█' * length}[/{color}]"


def show_dashboard():
    """Show the big picture: totals, charts, top reporters and latest reports."""
    reports = load_reports()
    if not reports:
        console.print("[yellow]No reports yet. The dashboard needs some data first.[/yellow]")
        return
    stats = build_stats(reports, load_cases())

    console.print("\n[bold {THEME}]═════════════ 📊 DASHBOARD ═════════════[/bold {THEME}]")
    console.print(
        f"👥 Users: [bold]{stats['users']}[/bold]   "
        f"📥 Reports: [bold]{stats['total_reports']}[/bold]   "
        f"🔴 Threats: [bold red]{stats['threats']}[/bold red]   "
        f"📁 Open cases: [bold]{stats['open_cases']}[/bold]"
    )

    console.print("\n[bold]─── Reports by type ───[/bold]")
    biggest = max(stats["by_type"].values())
    for scan_type, count in stats["by_type"].items():
        console.print(f"  {scan_type:<10} {draw_bar(count, biggest, THEME)} {count}")

    console.print("\n[bold]─── Risk levels ───[/bold]")
    biggest = max(stats["by_status"].values())
    for status in ("danger", "warning", "safe"):
        count = stats["by_status"].get(status, 0)
        color, label = STATUS_STYLES[status]
        console.print(f"  {label:<12} {draw_bar(count, biggest, color)} {count}")

    console.print("\n[bold]─── Most active reporters ───[/bold]")
    reporters = map(lambda pair: f"{pair[0]} ({pair[1]})", stats["top_reporters"])
    console.print("  " + "   ".join(reporters))

    if stats["top_tags"]:
        console.print("\n[bold]─── Top threat tags ───[/bold]")
        tags = map(lambda pair: f"{pair[0]} ({pair[1]})", stats["top_tags"])
        console.print("  " + "   ".join(tags))

    if stats["password_checks"]:
        percent = round(stats["leaked_passwords"] / stats["password_checks"] * 100)
        console.print("\n[bold]─── Leaked passwords ───[/bold]")
        console.print(
            f"  ⚠️ {stats['leaked_passwords']} of {stats['password_checks']} "
            f"checked passwords were leaked ({percent}%)"
        )

    console.print()
    show_reports_table(stats["latest"], "🕒 Latest reports", show_user=True)


# Campaign
def show_campaign(number, campaign):
    """Show one campaign: its reports, the evidence and the confidence."""
    reports = campaign["reports"]
    lines = [f"{len(reports)} reports from {len(campaign['users'])} user(s) share the same source:", ""]
    for report in reports:
        lines.append(f"  #{report.report_id:<3} {report.user:<8} {report.target}")
    lines.append("")
    lines.append("Evidence:")
    lines.extend(map(lambda reason: f"  ✔ {reason}", campaign["evidence"]))
    lines.append("")
    lines.append(f"Confidence: {campaign['confidence']}%")
    console.print(Panel("\n".join(lines), title=f"🚨 CAMPAIGN #{number}", border_style="red"))


def act_on_campaign(campaign):
    """Turn a campaign into a new case, or add it to an existing one."""
    show_menu("WHAT DO YOU WANT TO DO?", ALERT_ACTIONS)
    choice = ask_choice("Choose: ", get_keys(ALERT_ACTIONS))
    if choice == "0":
        return

    cases = load_cases()
    if choice == "1":
        case = Case(title=ask_text("Case title: "), case_id=next_case_id(cases))
        cases.append(case)
    else:
        case = ask_case(cases)
        if case is None:
            return

    for report in campaign["reports"]:
        case.add_report(report.report_id)
    case.add_note(f"Linked by correlation: {'; '.join(campaign['evidence'])}")
    save_cases(cases)
    console.print(f"[green]✅ {len(campaign['reports'])} reports linked to case #{case.case_id}.[/green]")


def show_correlation_alerts():
    """Find linked threats and let the admin act on one of them."""
    campaigns = open_campaigns(load_reports(), load_cases())
    if not campaigns:
        console.print("[green]✅ No new linked threats. All campaigns are handled.[/green]")
        return

    console.print(f"\n[bold red]🚨 {len(campaigns)} campaign(s) detected[/bold red]")
    for number, campaign in enumerate(campaigns, start=1):
        show_campaign(number, campaign)

    numbers = list(map(str, range(1, len(campaigns) + 1)))
    answer = ask_choice("Campaign number to act on (0 to go back): ", numbers + ["0"])
    if answer != "0":
        act_on_campaign(campaigns[int(answer) - 1])


# The lists
def export_menu():
    """Let the admin export a case report or a full summary as a text file."""
    show_menu("EXPORT REPORT", EXPORT_OPTIONS)
    choice = ask_choice("Choose: ", get_keys(EXPORT_OPTIONS))
    if choice == "0":
        return

    reports = load_reports()
    if choice == "1":
        case = ask_case(load_cases())
        if case is None:
            return
        path = export_case(case, reports)
    else:
        if not reports:
            console.print("[yellow]No reports yet. Nothing to export.[/yellow]")
            return
        path = export_summary(build_stats(reports, load_cases()))

    console.print(f"[green]✅ Report saved: {path}[/green]")


def cases_menu():
    """Admin loop for managing cases."""
    while True:
        cases = load_cases()
        show_menu("CASES", CASE_OPTIONS)
        choice = ask_choice("Choose: ", get_keys(CASE_OPTIONS))
        if choice == "0":
            return
        if choice == "1":
            create_case(cases)
        elif choice == "2":
            list_cases(cases)
        elif choice == "3":
            search_cases(cases)
        elif choice == "4":
            edit_case(cases)
        elif choice == "5":
            delete_case(cases)


def admin_menu():
    """Main loop for the admin."""
    while True:
        alerts = len(open_campaigns(load_reports(), load_cases()))
        if alerts:
            console.print(f"\n[bold red]🚨 {alerts} correlation alert(s)! Check option 3.[/bold red]")

        show_menu("ADMIN PANEL", ADMIN_OPTIONS)
        choice = ask_choice("Choose: ", get_keys(ADMIN_OPTIONS))

        if choice == "0":
            console.print("[{THEME}]🔒 Logged out.[/{THEME}]")
            return
        if choice == "1":
            show_all_reports()
        elif choice == "2":
            cases_menu()
        elif choice == "3":
            show_correlation_alerts()
        elif choice == "4":
            show_dashboard()
        elif choice == "5":
            export_menu()