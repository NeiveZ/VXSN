#!/usr/bin/env python3
# modules/redirect.py — Open Redirect scanner for VXSN

import urllib.parse
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_finding, print_section

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/",
    "///evil.com",
    "////evil.com",
    "/\\evil.com",
    "https:evil.com",
    "https://evil.com/%2f..",
    "https://evil.com/..",
    "%2f%2fevil.com",
    "%5c%5cevil.com",
    "https%3A%2F%2Fevil.com",
    "//evil%2Ecom",
    "/%09/evil.com",
    "/\tevil.com",
    "https://evil.com?",
    "https://evil.com#",
    "https://evil.com\\@target.com",
    "https://target.com@evil.com",
    "https://evil.com%00",
]

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "return_to", "next", "next_url", "goto",
    "destination", "dest", "target", "to", "link", "location",
    "continue", "forward", "callback", "redir", "ref", "referer",
    "path", "data", "site", "html", "uri", "page",
]

EVIL_DOMAIN = "evil.com"


class OpenRedirectScanner(BaseModule):

    NAME        = "vuln/redirect"
    DESCRIPTION = "Open Redirect — parameter-based redirect detection"
    SEVERITY    = "MEDIUM"
    REFERENCES  = [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
        "https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
    ]

    def _define_options(self):
        self._add_option("TARGET",  "",    True,  "Target URL (e.g. https://site.com/login)")
        self._add_option("PARAM",   "",    False, "Specific parameter to test (default: common redirect params)")
        self._add_option("TIMEOUT", "10",  False, "Request timeout in seconds")
        self._add_option("DELAY",   "0",   False, "Delay between requests in seconds")

    def run(self) -> list:
        if not self._validate():
            return []

        target = self.get_option("TARGET").strip()
        self.client = self._init_client()
        # Never follow redirects — we need to catch the Location header
        self.client.follow_redirects = False

        # Determine params to test
        specific = self.get_option("PARAM")
        if specific:
            test_params = [specific]
        elif "?" in target:
            qs = target.split("?", 1)[1]
            test_params = list(dict(urllib.parse.parse_qsl(qs)).keys())
        else:
            test_params = REDIRECT_PARAMS

        base_url = target.split("?")[0] if "?" in target else target

        print_section(f"Open Redirect Scan — {target}")
        print_status(f"Parameters : {Colors.WHITE}{test_params[:10]}{Colors.RESET}", "info")
        print_status(f"Payloads   : {Colors.WHITE}{len(REDIRECT_PAYLOADS)}{Colors.RESET}", "info")
        print()

        findings = []

        for param in test_params:
            print_status(f"Testing parameter: {Colors.CYAN}{param}{Colors.RESET}", "run")
            for payload in REDIRECT_PAYLOADS:
                code, body, headers = self.client.get(base_url, params={param: payload})

                if code == 0:
                    continue

                # Check for redirect to evil domain
                location = headers.get("location", headers.get("Location", ""))
                if location and EVIL_DOMAIN in location:
                    f = self._finding(
                        "Open Redirect", target, param, payload,
                        evidence=f"Location header: {location}"
                    )
                    print_finding(f["type"], target, param, payload,
                                  f["severity"], f["evidence"])
                    findings.append(f)
                    break

                # Also check body for meta refresh or JS redirect
                if EVIL_DOMAIN in body.lower():
                    body_snippet = next(
                        (line.strip() for line in body.splitlines()
                         if EVIL_DOMAIN in line.lower()), ""
                    )
                    f = self._finding(
                        "Open Redirect (Body)", target, param, payload,
                        evidence=f"Found in body: {body_snippet[:100]}"
                    )
                    print_finding(f["type"], target, param, payload,
                                  f["severity"], f["evidence"])
                    findings.append(f)
                    break

            if any(f["param"] == param for f in findings):
                continue

        print()
        if findings:
            print_status(f"Found {Colors.RED}{len(findings)}{Colors.RESET} Open Redirect(s).", "ok")
        else:
            print_status("No Open Redirect vulnerabilities detected.", "safe")

        return findings
