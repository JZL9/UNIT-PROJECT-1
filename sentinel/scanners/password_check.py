import hashlib

from sentinel.scanners.base import Scanner

API_URL = "https://api.pwnedpasswords.com/range/"


class PasswordScanner(Scanner):
    """Check if a password appeared in known data breaches (k-Anonymity)."""

    name = "Password Leak Check"

    def scan(self, password):
        """Return a result dict with status, risk, summary and advice."""
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        response = self.get(API_URL + prefix)
        count = self.find_count(response.text, suffix)
        return self.build_result(count)

    def find_count(self, response_text, suffix):
        """Search the API response for our suffix. Return how many times it leaked."""
        for line in response_text.splitlines():
            line_suffix, count = line.split(":")
            if line_suffix == suffix:
                return int(count)
        return 0

    def build_result(self, count):
        """Turn the leak count into a result the UI can display."""
        if count == 0:
            return {
                "status": "safe",
                "risk": 0,
                "summary": "Not found in any known data breach.",
                "advice": ["Still use a unique password for every site."],
            }

        risk = 100 if count >= 100 else 80
        return {
            "status": "danger",
            "risk": risk,
            "summary": f"Found {count:,} times in leaked data!",            "advice": [
                "Change this password immediately.",
                "Never reuse it on any other site.",
                "Use a password manager.",
            ],
        }