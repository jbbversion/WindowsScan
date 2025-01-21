import requests
import re

class ExploitDetector:
    def __init__(self):
        self.exploits = []

    def detect_exploits(self, target):
        self._check_sql_injection(target)
        self._check_xss(target)
        self._check_rce(target)
        return self.exploits

    def _check_sql_injection(self, target):
        payload = "' OR '1'='1"
        response = requests.get(f"{target}?id={payload}")
        if "error in your SQL syntax" in response.text:
            self.exploits.append(f"SQL Injection vulnerability detected at {target}")

    def _check_xss(self, target):
        payload = "<script>alert('XSS')</script>"
        response = requests.get(f"{target}?q={payload}")
        if payload in response.text:
            self.exploits.append(f"XSS vulnerability detected at {target}")

    def _check_rce(self, target):
        payload = "; ls -la"
        response = requests.get(f"{target}?cmd={payload}")
        if "file1.txt" in response.text:
            self.exploits.append(f"RCE vulnerability detected at {target}")￼Enter
