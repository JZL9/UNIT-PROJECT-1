import hashlib
import secrets
from pwinput import pwinput

from rich.console import Console

from sentinel.storage import load_json, save_json

console = Console()

ADMIN_FILE = "admin.json"
MAX_ATTEMPTS = 3


def hash_password(password, salt):
    """Return a secure hash of the password using the given salt."""
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return hashed.hex()


def ask_new_password():
    """Ask for a new password twice until both match and it is long enough."""
    while True:
        password = pwinput("Choose a password (min 6 characters): ", mask="*")
        if len(password) < 6:
            console.print("[red]❌ Password is too short.[/red]")
            continue
        confirm = pwinput("Confirm password: ", mask="*")        
        if password != confirm:
            console.print("[red]❌ Passwords don't match. Try again.[/red]")
            continue
        return password


def create_admin():
    """Create the admin account the first time the program runs."""
    console.print("[yellow]No admin account found. Let's create one.[/yellow]")
    username = ""
    while True:
        username = input("Choose a username (letters only, min 3): ").strip()   
        if len(username) >= 3 and username.isalpha(): 
             break
        console.print("[red]❌ Invalid username.[/red]")

    password = ask_new_password()
    salt = secrets.token_hex(16)
    admin = {
        "username": username,
        "salt": salt,
        "password_hash": hash_password(password, salt),
    }
    save_json(ADMIN_FILE, admin)
    console.print("[green]✅ Admin account created. Please log in.[/green]")
    return admin


def admin_login():
    """Ask for admin credentials. Return True if login succeeds."""
    admin = load_json(ADMIN_FILE, None)
    if admin is None:
        admin = create_admin()

    for attempt in range(MAX_ATTEMPTS, 0, -1):
        username = input("Username: ").strip()
        password = pwinput("Password: ", mask="*")
        entered_hash = hash_password(password, admin["salt"])

        if username == admin["username"] and secrets.compare_digest(entered_hash, admin["password_hash"]):
            console.print("[green]✅ Access granted. Welcome, admin.[/green]")
            return True

        remaining = attempt - 1
        if remaining > 0:
            word = "attempt" if remaining == 1 else "attempts"
            console.print(f"[red]❌ Wrong username or password. ({remaining} {word} left)[/red]")
    return False

