import os
from urllib.parse import urlparse

from dotenv import load_dotenv

from sentinel.scanners.base import Scanner, ScannerError

load_dotenv()

URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


class URLScanner(Scanner):
    """Check a URL and its domain against the URLhaus malware database."""

    name = "URL Reputation Check"

    def __init__(self):
        """Load the API key. Stop early if it is missing."""
        api_key = os.getenv("URLHAUS_AUTH_KEY")
        if not api_key:
            raise ScannerError("URLhaus API key is missing. Add it to your .env file.")
        self.__headers = {"Auth-Key": api_key}
    @staticmethod
    def normalize(url):
        """Add http:// if the user didn't type it."""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url

    @staticmethod
    def is_valid_url(url):
        """Basic check: no spaces, and the host must contain a dot."""
        if not url or " " in url.strip():
            return False
        host = urlparse(URLScanner.normalize(url)).hostname
        return host is not None and "." in host

    def scan(self, url):
        """Check the exact URL first, then the whole domain."""
        url = self.normalize(url)
        host = urlparse(url).hostname

        url_data = self.post(URL_ENDPOINT, headers=self.__headers, data={"url": url}).json()        
        if url_data.get("query_status") == "ok":
            return self._build_url_result(url_data)
        
        host_data = self.post(HOST_ENDPOINT, headers=self.__headers, data={"host": host}).json()
        if host_data.get("query_status") == "ok":
            return self._build_host_result(host_data)
        
        return self._build_clean_result()

    
    def _build_url_result(self, data):
        """The exact URL is in the database: high danger."""
        tags = data.get("tags") or []
        is_online = data.get("url_status") == "online"
        return {
            "status": "danger",
            "risk": 95 if is_online else 80,
            "summary": "This exact URL is listed as MALICIOUS.",
            "details": [
                f"Threat: {data.get('threat', 'unknown')}",
                f"Tags: {', '.join(tags) or 'none'}",
                f"Status now: {data.get('url_status', 'unknown')}",
                f"First reported: {data.get('date_added', 'unknown')}",
            ],
            "advice": [
                "Do NOT open this link.",
                "Do NOT download anything from it.",
                "Delete the message that contained it.",
            ],
        }

    def _build_host_result(self, data):
        """The URL isn't listed, but its domain hosted malware before: warning."""
        count = int(data.get("url_count", 0))
        return {
            "status": "warning",
            "risk": 70 if count >= 5 else 55,
            "summary": f"This domain hosted {count} malicious URL(s) before.",
            "details": [f"First seen: {data.get('firstseen', 'unknown')}"],
            "advice": [
                "Be very careful with any link from this domain.",
                "Don't enter passwords or personal data on it.",
            ],
        }

    def _build_clean_result(self):
        """Nothing found in the database."""
        return {
            "status": "safe",
            "risk": 0,
            "summary": "Not found in the URLhaus malware database.",
            "advice": [
                "Not being listed doesn't guarantee safety.",
                "New phishing sites appear every day, so stay careful.",
            ],
        }