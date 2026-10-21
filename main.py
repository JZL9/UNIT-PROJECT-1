from sentinel.storage import load_json, save_json

reports = load_json("reports.json", [])
print("Before:", reports)

reports.append({"user": "Fahad", "type": "test"})
save_json("reports.json", reports)
print("After:", reports)