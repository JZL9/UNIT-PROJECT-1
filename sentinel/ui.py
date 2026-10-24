from pwinput import pwinput
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinel.auth import admin_login
from sentinel.models import Report
from sentinel.report_store import load_reports, save_report
from sentinel.risk import combine_results
from sentinel.scanners.base import ScannerError
from sentinel.scanners.password_check import PasswordScanner
from sentinel.scanners.url_check import URLScanner
from sentinel.scanners.website_check import WebsiteScanner

console = Console()

START_OPTIONS = [
    ("1", "👤 User   — scan links & passwords"),
    ("2", "🔐 Admin  — analyze reports & cases"),
    ("0", "Exit"),
]

USER_OPTIONS = [
    ("1", "🔑 Check Password Leak"),
    ("2", "🔍 Investigate URL"),
    ("3", "📜 My Scans"),
    ("0", "Back"),
]

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

STATUS_STYLES = {
    "safe": ("green", "🟢 SAFE"),
    "warning": ("yellow", "🟠 WARNING"),
    "danger": ("red", "🔴 DANGER"),
}


def show_banner():
    """Display the program title."""
    console.print(Panel.fit(
        "[bold cyan]🛡️  SentinelCLI v1.0[/bold cyan]\nScan it before you click it.",
        border_style="cyan",
    ))


def show_menu(title, options):
    """Print a menu title and its options."""
    console.print(f"\n[bold cyan]═════ {title} ═════[/bold cyan]")
    for key, label in options:
        console.print(f"[{key}] {label}")


def get_keys(options):
    """Return only the option numbers, e.g. ['1', '2', '0']."""
    return list(map(lambda option: option[0], options))


def ask_choice(prompt, valid_choices):
    """Keep asking until the user enters one of the valid choices."""
    while True:
        choice = input(prompt).strip()
        if choice in valid_choices:
            return choice
        console.print(f"[red]❌ Invalid choice. Choose from: {', '.join(valid_choices)}[/red]")


def ask_name():
    """Keep asking until the user enters a valid name."""
    while True:
        name = input("Enter your name: ").strip()
        if len(name) >= 2 and name.replace(" ", "").isalpha():
            return name.title()
        console.print("[red]❌ Please enter a valid name (letters only, at least 2).[/red]")


def show_result(result):
    """Display any scan result inside a colored box, then the advice."""
    color, label = STATUS_STYLES[result["status"]]
    lines = [label, result["summary"]]
    lines.extend(result.get("details", []))
    lines.append(f"Risk: {result['risk']}/100")
    body = "\n".join(lines)
    console.print(Panel(body, title="Result", border_style=color))
    console.print("[bold]💡 Advice:[/bold]")
    for tip in result["advice"]:
        console.print(f"  • {tip}")


def check_password(name):
    """Ask for a password and check if it was leaked."""
    console.print("\n[bold]🔑 PASSWORD LEAK CHECK[/bold]")
    console.print("[dim]Your password is never sent or stored. 🔒[/dim]")

    password = pwinput("Enter password: ", mask="*")
    if not password:
        console.print("[red]❌ Password cannot be empty.[/red]")
        return

    try:
        with console.status("Checking known breaches..."):
            result = PasswordScanner().scan(password)
    except ScannerError as error:
        console.print(f"[red]❌ {error}[/red]")
        return

    show_result(result)
    save_report(Report.from_result(name, "password", "********", result))

def ask_url():
    """Keep asking for a valid URL. Return None if the user types 'back'."""
    while True:
        url = input("Enter URL (or 'back'): ").strip()
        if url.lower() == "back":
            return None
        if URLScanner.is_valid_url(url):
            return url
        console.print("[red]❌ That doesn't look like a valid URL. Example: example.com[/red]")


def investigate_url(name):
    """Check the URL's reputation first, then inspect the website if it's not known as malicious."""
    console.print("\n[bold]🔍 INVESTIGATE URL[/bold]")
    url = ask_url()
    if url is None:
        return

    try:
        with console.status("Checking reputation (URLhaus)..."):
            reputation = URLScanner().scan(url)

        if reputation["status"] == "danger":
            result = reputation
            console.print("[dim]🛡️ Known malicious: live checks skipped for your safety.[/dim]")
        else:
            console.print("[dim]⚠️ Live checks contact the website directly (headers only).[/dim]")
            with console.status("Inspecting SSL, DNS and uptime..."):
                website = WebsiteScanner().scan(URLScanner.get_host(url))
            result = combine_results(reputation, website)
    except ScannerError as error:
        console.print(f"[red]❌ {error}[/red]")
        return

    show_result(result)
    save_report(Report.from_result(name, "url", URLScanner.normalize(url), result))
    console.print("[dim]📥 Report saved for the security team.[/dim]")



def show_reports_table(reports, title, show_user=False):
    """Print a table of reports. The admin view also shows the user column."""
    table = Table(title=title)
    table.add_column("#", justify="right")
    table.add_column("Date", no_wrap=True)
    if show_user:
        table.add_column("User")
    table.add_column("Type")
    table.add_column("Target", overflow="fold")
    table.add_column("Risk", justify="right")

    for report in reports:
        color, _ = STATUS_STYLES[report.status]
        row = [str(report.report_id), report.created_at]
        if show_user:
            row.append(report.user)
        row.extend([report.scan_type, report.target, f"[{color}]{report.risk}[/{color}]"])
        table.add_row(*row)

    console.print(table)
    


def show_my_scans(name):
    """Show a table of all scans made by this user."""
    my_reports = list(filter(lambda report: report.user == name, load_reports()))
    if not my_reports:
        console.print("[yellow]You haven't scanned anything yet. Try option 1 or 2![/yellow]")
        return
    show_reports_table(my_reports, f"📜 YOUR SCANS — {name}")


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


def ask_report_id(reports):
    """Ask for an ID from the shown reports. Return that Report, or None to go back."""
    ids = list(map(lambda report: str(report.report_id), reports))
    while True:
        answer = input("Report ID for details (Enter to go back): ").strip()
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


def user_menu(name):
    """Main loop for a normal user."""
    while True:
        show_menu(f"USER MENU — {name}", USER_OPTIONS)
        choice = ask_choice("Choose: ", get_keys(USER_OPTIONS))
        if choice == "0":
            return
        if choice == "1":
            check_password(name)
        elif choice == "2":
            investigate_url(name)
        elif choice == "3":
            show_my_scans(name)
        else:
            console.print("[yellow]🚧 Coming soon...[/yellow]")


def admin_menu():
    """Main loop for the admin."""
    while True:
        show_menu("ADMIN PANEL", ADMIN_OPTIONS)
        choice = ask_choice("Choose: ", get_keys(ADMIN_OPTIONS))
        if choice == "0":
            console.print("[cyan]🔒 Logged out.[/cyan]")
            return
        if choice == "1":
            show_all_reports()
        else:
            console.print("[yellow]🚧 Coming soon...[/yellow]")


def start_menu():
    """First screen: ask who is using the program."""
    while True:
        show_banner()
        show_menu("WHO ARE YOU?", START_OPTIONS)
        choice = ask_choice("Choose: ", get_keys(START_OPTIONS))

        if choice == "1":
            name = ask_name()
            console.print(f"[green]👋 Welcome, {name}![/green]")
            user_menu(name)
        elif choice == "2":
            if admin_login():
                admin_menu()
        else:
            console.print("[cyan]👋 Stay safe! Goodbye.[/cyan]")
            break