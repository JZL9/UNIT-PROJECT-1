import ipaddress
import socket
import ssl
import time

import requests

from sentinel.scanners.base import Scanner

SSL_PORT = 443
SECONDS_PER_DAY = 86400
DNS_API = "https://dns.google/resolve"
RECORD_CODES = {"A": 1, "MX": 15}
NEW_CERT_DAYS = 7
RISK_POINTS = {
    "raw_ip": 30,
    "invalid_ssl": 40,
    "no_https": 25,
    "new_cert": 25,
    "no_mx": 10,
    "down": 5,
}


class WebsiteScanner(Scanner):
    """Inspect a website directly: SSL certificate, DNS records and uptime."""

    name = "Website Inspection"

    def _check_ssl(self, host):
        """Connect on port 443 and read the site's certificate."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, SSL_PORT), timeout=self.TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                    cert = secure_sock.getpeercert()

        except ssl.SSLCertVerificationError as error:
            return {"ok": False, "reason": "invalid", "error": f"Invalid certificate: {error.verify_message}"}
        except socket.gaierror:
            return {"ok": False, "reason": "no_domain", "error": "Domain does not exist."}        
        except OSError:
            return {"ok": False, "reason": "no_https", "error": "No HTTPS (port 443 is closed or not responding)."}        

        issuer = {}
        for part in cert["issuer"]:
            key, value = part[0]
            issuer[key] = value

        now = time.time()
        valid_from = ssl.cert_time_to_seconds(cert["notBefore"])
        valid_until = ssl.cert_time_to_seconds(cert["notAfter"])

        return {
            "ok": True,
            "issuer": issuer.get("organizationName", "Unknown"),
            "age_days": int((now - valid_from) // SECONDS_PER_DAY),
            "days_left": int((valid_until - now) // SECONDS_PER_DAY),
        }

    @staticmethod
    def _is_ip(host):
        """True if the host is an IP address like 1.2.3.4 (not a domain name)."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
        
    def _dns_query(self, host, record_type):
        """Ask Google DNS for one record type. Return a list of answers."""
        response = self.get(f"{DNS_API}?name={host}&type={record_type}")
        answers = response.json().get("Answer", [])
        matching = filter(lambda answer: answer["type"] == RECORD_CODES[record_type], answers)
        return list(map(lambda answer: answer["data"], matching))

    def _check_dns(self, host):
        """Find the site's IP address and whether it has mail records."""
        if self._is_ip(host):
            return {"ip": host, "has_mx": False, "is_raw_ip": True}

        ips = self._dns_query(host, "A")
        mail_servers = self._dns_query(host, "MX")
        return {
            "ip": ips[0] if ips else None,
            "has_mx": bool(mail_servers),
            "is_raw_ip": False,
        }

    def _check_uptime(self, host):
        """Send a HEAD request (headers only, no page content) and time it."""
        for scheme in ("https", "http"):
            try:
                response = requests.head(
                    f"{scheme}://{host}", timeout=self.TIMEOUT, allow_redirects=True
                )
            except requests.exceptions.SSLError:
                return {"is_up": True, "status_code": None, "seconds": None}
            except requests.RequestException:
                continue
            return {
                "is_up": response.status_code < 500,
                "status_code": response.status_code,
                "seconds": round(response.elapsed.total_seconds(), 2),
            }
        return {"is_up": False, "status_code": None, "seconds": None}

    def scan(self, host):
        """Run DNS, SSL and uptime checks, then score the findings."""
        dns_info = self._check_dns(host)
        if dns_info["ip"] is None:
            return {
                "status": "warning",
                "risk": 40,
                "summary": "This domain does not exist (no DNS records).",
                "advice": ["Check the spelling. Fake links often use misspelled domains."],
                "indicators": {"ip": None, "ssl_issuer": None},
            }

        ssl_info = self._check_ssl(host)
        uptime = self._check_uptime(host)
        risk, findings = self._score(dns_info, ssl_info, uptime)
        status = self.status_from_risk(risk)

        summaries = {
            "safe": "No obvious red flags found on the website.",
            "warning": "Some suspicious signs found on the website.",
            "danger": "Several red flags found on the website!",
        }
        advice = {
            "safe": ["The site looks technically normal, but always stay careful."],
            "warning": ["Avoid entering passwords or personal data on this site."],
            "danger": ["Do NOT trust this site.", "Do NOT enter any information on it."],
        }
        return {
            "status": status,
            "risk": risk,
            "summary": summaries[status],
            "details": findings,
            "advice": advice[status],
            "indicators": {"ip": dns_info["ip"], "ssl_issuer": ssl_info.get("issuer")},
        }

    def _score(self, dns_info, ssl_info, uptime):
        """Add risk points for every red flag. Return (risk, findings)."""
        risk = 0
        findings = []

        if dns_info["is_raw_ip"]:
            risk += RISK_POINTS["raw_ip"]
            findings.append("⚠️ Uses a raw IP address instead of a domain name")
        else:
            findings.append(f"🌐 IP address: {dns_info['ip']}")
            if dns_info["has_mx"]:
                findings.append("✅ DNS: mail (MX) records found")
            else:
                risk += RISK_POINTS["no_mx"]
                findings.append("⚠️ DNS: no mail (MX) records")

        if ssl_info["ok"]:
            findings.append(f"✅ SSL: issued by {ssl_info['issuer']}, {ssl_info['days_left']} days left")
            if ssl_info["age_days"] < NEW_CERT_DAYS:
                risk += RISK_POINTS["new_cert"]
                findings.append(f"⚠️ Certificate is only {ssl_info['age_days']} day(s) old")
        elif ssl_info["reason"] == "invalid":
            risk += RISK_POINTS["invalid_ssl"]
            findings.append(f"🔴 SSL: {ssl_info['error']}")
        else:
            risk += RISK_POINTS["no_https"]
            findings.append(f"⚠️ SSL: {ssl_info['error']}")

        if uptime["is_up"]:
            speed = f" ({uptime['seconds']}s)" if uptime["seconds"] else ""
            findings.append(f"✅ Online{speed}")
        else:
            risk += RISK_POINTS["down"]
            findings.append("⚠️ Not responding")

        return min(risk, 100), findings