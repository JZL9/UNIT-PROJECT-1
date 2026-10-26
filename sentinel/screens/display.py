from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
THEME = "bright_green"

STATUS_STYLES = {
    "safe": ("green", "🟢 SAFE"),
    "warning": ("yellow", "🟠 WARNING"),
    "danger": ("red", "🔴 DANGER"),
}


def show_banner():
    """Display the program title."""
    console.print(Panel.fit(
        f"[bold {THEME}]🛡️  SentinelCLI v1.0[/bold {THEME}]\nScan it before you click it.",
        border_style=THEME,
    ))


def show_menu(title, options):
    """Print a menu title and its options."""
    console.print(f"\n[bold{THEME}]═════ {title} ═════[/bold{THEME}]")
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


def ask_text(prompt, min_length=3):
    """Keep asking until the text is long enough."""
    while True:
        text = input(prompt).strip()
        if len(text) >= min_length:
            return text
        console.print(f"[red]❌ Please write at least {min_length} characters.[/red]")


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