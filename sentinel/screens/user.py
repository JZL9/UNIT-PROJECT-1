from pwinput import pwinput

from sentinel.models import Report
from sentinel.report_store import load_reports, save_report
from sentinel.risk import combine_results
from sentinel.scanners.base import ScannerError
from sentinel.scanners.password_check import PasswordScanner
from sentinel.scanners.url_check import URLScanner
from sentinel.scanners.website_check import WebsiteScanner
from sentinel.screens.display import (
    ask_choice,
    console,
    get_keys,
    show_menu,
    show_reports_table,
    show_result,
)

USER_OPTIONS = [
    ("1", "🔑 Check Password Leak"),
    ("2", "🔍 Investigate URL"),
    ("3", "📜 My Scans"),
    ("0", "Back"),
]


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
            result["indicators"] = WebsiteScanner().lookup_indicators(URLScanner.get_host(url))
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


def show_my_scans(name):
    """Show a table of all scans made by this user."""
    my_reports = list(filter(lambda report: report.user == name, load_reports()))
    if not my_reports:
        console.print("[yellow]You haven't scanned anything yet. Try option 1 or 2![/yellow]")
        return
    show_reports_table(my_reports, f"📜 YOUR SCANS — {name}")


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