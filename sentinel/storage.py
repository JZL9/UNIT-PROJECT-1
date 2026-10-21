import json
import os

DATA_FOLDER = "data"

def ensure_data_folder():
    """Create the data folder if it doesn't exist."""
    os.makedirs(DATA_FOLDER, exist_ok=True)


def load_json(filename, default):
    """Read a JSON file from the data folder. Return default if missing or broken."""
    path = os.path.join(DATA_FOLDER, filename)
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        print(f"Warning: {filename} is damaged Starting with empty data. ")
        return default


def save_json(filename, data):
    """Save data to a JSON file in the data folder."""
    ensure_data_folder()
    path = os.path.join(DATA_FOLDER, filename)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)
