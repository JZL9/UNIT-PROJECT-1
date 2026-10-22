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

    def request(self, method, url, headers=None, data=None, json_body=None):
        """Send any HTTP request and turn network problems into ScannerError."""
        try:
            response = requests.request(
                method, url, headers=headers, data=data, json=json_body, timeout=self.TIMEOUT
            )
            response.raise_for_status()
            return response
        except requests.ConnectionError:
            raise ScannerError("No internet connection.")
        except requests.Timeout:
            raise ScannerError("The service took too long to respond.")
        except requests.HTTPError as error:
            code = error.response.status_code
            if code in (401, 403):
                raise ScannerError("Invalid or missing API key.")
            raise ScannerError(f"Service error (code {code}).")

    def get(self, url, headers=None):
        """Shortcut for a GET request."""
        return self.request("GET", url, headers=headers)

    def post(self, url, headers=None, data=None, json_body=None):
        """Shortcut for a POST request."""
        return self.request("POST", url, headers=headers, data=data, json_body=json_body)