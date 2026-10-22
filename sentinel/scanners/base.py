import requests


class ScannerError(Exception):
    """Raised when a scan cannot be completed."""


class Scanner:
    """Parent class for all scanners."""

    name = "Scanner"
    TIMEOUT = 10

    def scan(self, target):
        """Every child scanner must write its own version of this method."""
        raise NotImplementedError("Child classes must implement scan()")

    def get(self, url, headers=None):
        """Send a GET request and turn network problems into ScannerError."""
        try:
            response = requests.get(url, headers=headers, timeout=self.TIMEOUT)
            response.raise_for_status()
            return response
        except requests.ConnectionError:
            raise ScannerError("No internet connection.")
        except requests.Timeout:
            raise ScannerError("The service took too long to respond.")
        except requests.HTTPError as error:
            raise ScannerError(f"Service error (code {error.response.status_code}).")