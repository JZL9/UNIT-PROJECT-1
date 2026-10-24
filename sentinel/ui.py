from pwinput import pwinput
from rich.console import Console
from rich.panel import Panel

from sentinel.auth import admin_login
from sentinel.models import Report
from sentinel.report_store import save_report
from sentinel.scanners.base import ScannerError
from sentinel.scanners.password_check import PasswordScanner
from sentinel.scanners.url_check import URLScanner

console = Console()

START_OPTIONS = [
    ("1", "👤 User   — scan links & passwords"),
    ("2", "🔐 Admin  — analyze reports & cases"),
    ("0", "Exit"),
]

USER_OPTIONS = [
    ("1", "🔑 Check Password Leak"),
    ("2", "🔍 Investigate URL"),
    ("3", "📦 Scan requirements.txt"),
    ("4", "📜 My Scans"),
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
    """Ask for a URL and check its reputation."""
    console.print("\n[bold]🔍 INVESTIGATE URL[/bold]")
    url = ask_url()
    if url is None:
        return

    try:
        scanner = URLScanner()
        with console.status("Checking reputation (URLhaus)..."):
            result = scanner.scan(url)
    except ScannerError as error:
        console.print(f"[red]❌ {error}[/red]")
        return

    show_result(result)
    save_report(Report.from_result(name, "url", URLScanner.normalize(url), result))
    console.print("[dim]📥 Report saved for the security team.[/dim]")


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