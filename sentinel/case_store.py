from sentinel.models import Case
from sentinel.storage import load_json, save_json

CASES_FILE = "cases.json"


def load_cases():
    """Load all saved cases as Case objects."""
    return list(map(Case.from_dict, load_json(CASES_FILE, [])))


def save_cases(cases):
    """Save the whole list of cases back to the file."""
    save_json(CASES_FILE, list(map(lambda case: case.to_dict(), cases)))


def next_case_id(cases):
    """Return the next free case ID."""
    return max(map(lambda case: case.case_id, cases), default=0) + 1


def find_case(cases, case_id):
    """Return the case with this ID, or None if it doesn't exist."""
    for case in cases:
        if case.case_id == case_id:
            return case
    return None