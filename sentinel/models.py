from datetime import datetime


def now_text():
    """Current date and time as text, e.g. '2026-10-25 08:30'."""
    return datetime.now().strftime("%Y-%m-%d %H:%M")


class Report:
    """One scan done by a user."""

    DANGER_LEVEL = 70

    def __init__(self, user, scan_type, target, status, risk, summary,
                details=None, indicators=None, report_id=None, created_at=None):
        self.report_id = report_id
        self.user = user
        self.scan_type = scan_type
        self.target = target
        self.status = status
        self.risk = risk
        self.summary = summary
        self.details = details or []
        self.indicators = indicators or {}
        self.created_at = created_at or now_text()

        
    @classmethod
    def from_result(cls, user, scan_type, target, result):
        """Build a Report from a scanner's result dict."""
        return cls(
            user=user,
            scan_type=scan_type,
            target=target,
            status=result["status"],
            risk=result["risk"],
            summary=result["summary"],
            details=result.get("details", []),
            indicators=result.get("indicators", {}),
        )

    @classmethod
    def from_dict(cls, data):
        """Build a Report from a dict loaded from JSON."""
        return cls(**data)

    def to_dict(self):
        """Turn the Report into a dict so it can be saved as JSON."""
        return {
            "report_id": self.report_id,
            "user": self.user,
            "scan_type": self.scan_type,
            "target": self.target,
            "status": self.status,
            "risk": self.risk,
            "summary": self.summary,
            "details": self.details,
            "indicators": self.indicators,
            "created_at": self.created_at,
        }

    def is_dangerous(self):
        """True if the risk is high."""
        return self.risk >= self.DANGER_LEVEL


class Case:
    """An investigation that groups related reports together."""

    STATUSES = ("open", "investigating", "closed")

    def __init__(self, title, report_ids=None, status="open", notes=None,
                 case_id=None, created_at=None):
        self.case_id = case_id
        self.title = title
        self.report_ids = report_ids or []
        self.status = status
        self.notes = notes or []
        self.created_at = created_at or now_text()

    @classmethod
    def from_dict(cls, data):
        """Build a Case from a dict loaded from JSON."""
        return cls(**data)

    def to_dict(self):
        """Turn the Case into a dict so it can be saved as JSON."""
        return {
            "case_id": self.case_id,
            "title": self.title,
            "report_ids": self.report_ids,
            "status": self.status,
            "notes": self.notes,
            "created_at": self.created_at,
        }

    def add_report(self, report_id):
        """Link a report to this case. Return False if it was already linked."""
        if report_id in self.report_ids:
            return False
        self.report_ids.append(report_id)
        return True

    def remove_report(self, report_id):
        """Unlink a report. Return False if it wasn't linked."""
        if report_id not in self.report_ids:
            return False
        self.report_ids.remove(report_id)
        return True

    def add_note(self, text):
        """Add a note with the current time in front of it."""
        self.notes.append(f"{now_text()} — {text}")

    def set_status(self, status):
        """Change the status. Raise ValueError if the status is not allowed."""
        if status not in self.STATUSES:
            raise ValueError(f"Status must be one of: {', '.join(self.STATUSES)}")
        self.status = status

    def average_risk(self, reports):
        """Average risk of the reports linked to this case (0 if none)."""
        linked = list(filter(lambda report: report.report_id in self.report_ids, reports))
        if not linked:
            return 0
        return round(sum(map(lambda report: report.risk, linked)) / len(linked))