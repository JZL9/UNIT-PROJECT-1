from pwinput import pwinput
from rich.console import Console
from rich.panel import Panel

from sentinel.auth import admin_login
from sentinel.scanners.base import ScannerError
from sentinel.scanners.password_check import PasswordScanner

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
    body = f"{label}\n{result['summary']}\nRisk: {result['risk']}/100"
    console.print(Panel(body, title="Result", border_style=color))
    console.print("[bold]💡 Advice:[/bold]")
    for tip in result["advice"]:
        console.print(f"  • {tip}")


def check_password():
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

    
def user_menu(name):
    """Main loop for a normal user."""
    while True:
        show_menu(f"USER MENU — {name}", USER_OPTIONS)
        choice = ask_choice("Choose: ", get_keys(USER_OPTIONS))
        if choice == "0":
            return
        if choice == "1":
            check_password()
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