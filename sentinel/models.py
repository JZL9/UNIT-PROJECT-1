from datetime import datetime


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
        self.created_at = created_at or datetime.now().strftime("%Y-%m-%d %H:%M")

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