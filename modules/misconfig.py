#!/usr/bin/env python3
# modules/misconfig.py — Misconfiguration scanner for VXSN

from modules.base import BaseModule
from utils.colors import Colors, print_status, print_finding, print_section

# ── Sensitive paths to probe ──────────────────────────────────────

SENSITIVE_PATHS = [
    ("/.env",                    "HIGH",   "Environment file"),
    ("/.env.bak",                "HIGH",   "Environment backup"),
    ("/.env.local",              "HIGH",   "Local environment file"),
    ("/.git/config",             "HIGH",   "Git config exposed"),
    ("/.git/HEAD",               "HIGH",   "Git HEAD exposed"),
    ("/.gitignore",              "LOW",    "Gitignore exposed"),
    ("/config.php",              "HIGH",   "PHP config file"),
    ("/config.php.bak",          "HIGH",   "PHP config backup"),
    ("/database.php",            "HIGH",   "Database config"),
    ("/db.php",                  "HIGH",   "Database file"),
    ("/backup.sql",              "HIGH",   "SQL backup"),
    ("/dump.sql",                "HIGH",   "SQL dump"),
    ("/wp-config.php",           "HIGH",   "WordPress config"),
    ("/wp-config.php.bak",       "HIGH",   "WordPress config backup"),
    ("/phpinfo.php",             "MEDIUM", "PHP info page"),
    ("/info.php",                "MEDIUM", "PHP info page"),
    ("/test.php",                "LOW",    "Test PHP file"),
    ("/debug.php",               "MEDIUM", "Debug page"),
    ("/admin/",                  "MEDIUM", "Admin panel"),
    ("/admin/config.php",        "HIGH",   "Admin config"),
    ("/server-status",           "MEDIUM", "Apache server-status"),
    ("/server-info",             "MEDIUM", "Apache server-info"),
    ("/.htaccess",               "MEDIUM", "Htaccess exposed"),
    ("/web.config",              "HIGH",   "IIS web config"),
    ("/crossdomain.xml",         "LOW",    "Crossdomain policy"),
    ("/sitemap.xml",             "INFO",   "Sitemap"),
    ("/robots.txt",              "INFO",   "Robots.txt"),
    ("/.DS_Store",               "LOW",    "Mac DS_Store file"),
    ("/composer.json",           "LOW",    "Composer config"),
    ("/package.json",            "LOW",    "NPM package file"),
    ("/Dockerfile",              "MEDIUM", "Dockerfile exposed"),
    ("/docker-compose.yml",      "HIGH",   "Docker Compose exposed"),
    ("/.bash_history",           "HIGH",   "Bash history exposed"),
    ("/id_rsa",                  "HIGH",   "SSH private key"),
    ("/credentials.txt",         "HIGH",   "Credentials file"),
    ("/passwords.txt",           "HIGH",   "Password file"),
]

# ── Security headers to check ─────────────────────────────────────

SECURITY_HEADERS = {
    "strict-transport-security": ("HIGH",   "Missing HSTS header"),
    "content-security-policy":   ("HIGH",   "Missing CSP header"),
    "x-content-type-options":    ("MEDIUM", "Missing X-Content-Type-Options"),
    "x-frame-options":           ("MEDIUM", "Missing X-Frame-Options (Clickjacking risk)"),
    "x-xss-protection":          ("LOW",    "Missing X-XSS-Protection"),
    "referrer-policy":           ("LOW",    "Missing Referrer-Policy"),
    "permissions-policy":        ("LOW",    "Missing Permissions-Policy"),
}

# ── Dangerous HTTP methods ────────────────────────────────────────

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]


class MisconfigScanner(BaseModule):

    NAME        = "vuln/misconfig"
    DESCRIPTION = "Misconfiguration scanner — exposed files, security headers, HTTP methods"
    SEVERITY    = "MEDIUM"
    REFERENCES  = [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/",
        "https://owasp.org/www-project-secure-headers/",
    ]

    def _define_options(self):
        self._add_option("TARGET",       "",     True,  "Target base URL (e.g. https://site.com)")
        self._add_option("TIMEOUT",      "10",   False, "Request timeout in seconds")
        self._add_option("DELAY",        "0",    False, "Delay between requests in seconds")
        self._add_option("CHECK_FILES",  "true", False, "Check for sensitive files (true/false)")
        self._add_option("CHECK_HEADERS","true", False, "Check security headers (true/false)")
        self._add_option("CHECK_METHODS","true", False, "Check dangerous HTTP methods (true/false)")

    def run(self) -> list:
        if not self._validate():
            return []

        target       = self.get_option("TARGET").strip().rstrip("/")
        check_files  = self.get_option("CHECK_FILES").lower()  == "true"
        check_headers= self.get_option("CHECK_HEADERS").lower()== "true"
        check_methods= self.get_option("CHECK_METHODS").lower()== "true"
        self.client  = self._init_client()

        print_section(f"Misconfig Scan — {target}")
        print_status(f"Sensitive files  : {Colors.WHITE}{check_files}{Colors.RESET}", "info")
        print_status(f"Security headers : {Colors.WHITE}{check_headers}{Colors.RESET}", "info")
        print_status(f"HTTP methods     : {Colors.WHITE}{check_methods}{Colors.RESET}", "info")
        print()

        findings = []

        # ── 1. Sensitive files ────────────────────────────────────
        if check_files:
            print_status("Checking sensitive paths...", "run")
            for path, severity, label in SENSITIVE_PATHS:
                url  = target + path
                code, body, _ = self.client.get(url)
                if code in (200, 301, 302, 403):
                    color = Colors.RED if severity == "HIGH" else Colors.YELLOW
                    sev_label = f"[{severity}]"
                    print(f"  {Colors.BOLD}{color}{sev_label}{Colors.RESET} "
                          f"{Colors.WHITE}{label}{Colors.RESET}  "
                          f"{Colors.DARK_GRAY}{url}  [{code}]{Colors.RESET}")
                    f = self._finding(
                        f"Exposed: {label}", url, "path", path,
                        severity=severity,
                        evidence=f"HTTP {code}"
                    )
                    findings.append(f)
            print()

        # ── 2. Security headers ───────────────────────────────────
        if check_headers:
            print_status("Checking security headers...", "run")
            code, _, headers = self.client.get(target)
            lower_headers = {k.lower(): v for k, v in headers.items()}

            for header, (severity, label) in SECURITY_HEADERS.items():
                present = header in lower_headers
                if not present:
                    color = Colors.RED if severity == "HIGH" else Colors.YELLOW
                    print(f"  {Colors.BOLD}{color}[{severity}]{Colors.RESET} "
                          f"{Colors.WHITE}{label}{Colors.RESET}  "
                          f"{Colors.DARK_GRAY}{header}{Colors.RESET}")
                    f = self._finding(
                        label, target, "header", header,
                        severity=severity,
                        evidence=f"Header '{header}' not present in response"
                    )
                    findings.append(f)
                else:
                    print(f"  {Colors.GREEN}[OK]{Colors.RESET} "
                          f"{Colors.DARK_GRAY}{header}{Colors.RESET}")
            print()

        # ── 3. HTTP methods ───────────────────────────────────────
        if check_methods:
            print_status("Checking dangerous HTTP methods...", "run")
            import urllib.request, ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            for method in DANGEROUS_METHODS:
                try:
                    req = urllib.request.Request(target, method=method)
                    handler = urllib.request.HTTPSHandler(context=ctx)
                    opener = urllib.request.build_opener(handler)
                    with opener.open(req, timeout=int(self.get_option("TIMEOUT"))) as resp:
                        code = resp.status
                except Exception as e:
                    code_str = str(e)
                    code = int(code_str.split(" ")[1]) if "HTTP Error" in code_str else 0

                if code not in (405, 501, 0):
                    print(f"  {Colors.BOLD}{Colors.RED}[HIGH]{Colors.RESET} "
                          f"Dangerous method allowed: {Colors.WHITE}{method}{Colors.RESET}  "
                          f"{Colors.DARK_GRAY}[{code}]{Colors.RESET}")
                    f = self._finding(
                        f"Dangerous HTTP Method: {method}", target, "method", method,
                        severity="HIGH",
                        evidence=f"Server responded with HTTP {code}"
                    )
                    findings.append(f)
                else:
                    print(f"  {Colors.GREEN}[OK]{Colors.RESET} "
                          f"{Colors.DARK_GRAY}{method} — {code}{Colors.RESET}")
            print()

        if findings:
            print_status(f"Found {Colors.RED}{len(findings)}{Colors.RESET} misconfiguration(s).", "ok")
        else:
            print_status("No misconfigurations detected.", "safe")

        return findings
