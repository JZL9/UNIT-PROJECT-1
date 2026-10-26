from sentinel.auth import admin_login
from sentinel.screens.admin import admin_menu
from sentinel.screens.display import ask_choice, ask_name, console, get_keys, show_banner, show_menu
from sentinel.screens.user import user_menu
from sentinel.screens.display import THEME
START_OPTIONS = [
    ("1", "👤 User   — scan links & passwords"),
    ("2", "🔐 Admin  — analyze reports & cases"),
    ("0", "Exit"),
]

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
            console.print(f"[{THEME}]👋 Stay safe! Goodbye.[/{THEME}]")
            break