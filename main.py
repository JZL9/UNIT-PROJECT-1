from sentinel.ui import start_menu


def main():
    """Start the program."""
    try:
        start_menu()
    except KeyboardInterrupt:
        print("\nGoodbye!")


if __name__ == "__main__":
    main()