from sentinel.models import Report
from sentinel.storage import load_json, save_json

REPORTS_FILE = "reports.json"


def load_reports():
    """Load all saved reports as Report objects."""
    return list(map(Report.from_dict, load_json(REPORTS_FILE, [])))


def save_report(report):
    """Give the report a new ID and add it to the reports file."""
    reports = load_json(REPORTS_FILE, [])
    report.report_id = max(map(lambda r: r["report_id"], reports), default=0) + 1
    reports.append(report.to_dict())
    save_json(REPORTS_FILE, reports)