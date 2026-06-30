# VXSN 

> Vulnerability & Exploit Scanner — modular web vulnerability scanner with Metasploit-style interactive shell.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

VXSN is a modular web vulnerability scanner built around an **interactive shell interface** — load a module, configure the target, run. Each module is independent and targets a specific vulnerability class. Results persist in session memory and can be exported as TXT, JSON, or HTML reports with severity breakdown.

---

## Modules

| Module | Vulnerability | Techniques |
|---|---|---|
| `vuln/sqli` | SQL Injection | Error-based, Boolean-based, Time-based |
| `vuln/xss` | Cross-Site Scripting | Reflected XSS — 15 payloads |
| `vuln/lfi` | Local File Inclusion | Path traversal, PHP wrappers, encoded bypasses |
| `vuln/redirect` | Open Redirect | 20 payloads, auto-detects redirect parameters |
| `vuln/misconfig` | Misconfiguration | 35 sensitive paths, security headers audit, HTTP methods |

---

## Features

- **Interactive shell** — `use`, `set`, `run`, `back` workflow identical to Metasploit
- **Session persistence** — findings accumulate across modules within a session
- **Auto-detection** — redirect module auto-detects common redirect parameters
- **Security header audit** — checks CSP, HSTS, X-Frame-Options, and more
- **HTTP method testing** — detects dangerous methods (PUT, DELETE, TRACE, CONNECT)
- **Report generation** — TXT, JSON, or HTML with severity summary
- **Auto-save** — every scan auto-saves to `reports/` as JSON
- **Shared HTTP client** — UA rotation, SSL bypass, redirect control across all modules
- **Zero required API keys** — all modules work out of the box

---

## Requirements

| Dependency | Purpose | Install |
|---|---|---|
| `python 3.10+` | Runtime | `apt install python3` |

```bash
sudo apt install python3
```

No external Python packages required — uses only the standard library.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/NeiveZ/VXSN.git
cd VXSN
```

### 2. Make executable

```bash
chmod +x vxsn.sh
```

### 3. (Optional) Install globally

```bash
sudo cp vxsn.sh /usr/local/bin/vxsn
```

### 4. Launch

```bash
./vxsn.sh
```

---

## Usage

```
vxsn > use <module>
vxsn > set <OPTION> <value>
vxsn > run
```

### Core commands

```
use <module>            Load a module
set <OPTION> <value>    Set a module option
run                     Execute the loaded module
options                 Show current module options
info                    Show module description and options
back                    Unload current module

show modules            List all available modules
show findings           View findings from current session
show session            Session statistics

report [txt|json|html]  Export findings to a report file
history                 Show scan history
clear                   Clear the screen
exit                    Quit VXSN
```

---

## Examples

**SQL Injection scan:**
```
vxsn > use vuln/sqli
vxsn (vuln/sqli) > set TARGET https://site.com/page.php?id=1
vxsn (vuln/sqli) > set LEVEL 2
vxsn (vuln/sqli) > run
```

**XSS scan on a specific parameter:**
```
vxsn > use vuln/xss
vxsn (vuln/xss) > set TARGET https://site.com/search.php?q=test
vxsn (vuln/xss) > set PARAM q
vxsn (vuln/xss) > run
```

**LFI scan:**
```
vxsn > use vuln/lfi
vxsn (vuln/lfi) > set TARGET https://site.com/index.php?file=home
vxsn (vuln/lfi) > run
```

**Open Redirect scan:**
```
vxsn > use vuln/redirect
vxsn (vuln/redirect) > set TARGET https://site.com/login
vxsn (vuln/redirect) > run
```

**Misconfiguration scan:**
```
vxsn > use vuln/misconfig
vxsn (vuln/misconfig) > set TARGET https://site.com
vxsn (vuln/misconfig) > run
```

**Generate HTML report:**
```
vxsn > report html engagement_report
```

---

## Output

```
vxsn (vuln/sqli) > run

── SQLi Scan — https://site.com/page.php?id=1 ──────────

[*] Parameters : ['id']
[*] Method     : GET
[*] Level      : 2

[*] Testing parameter: id

  [HIGH] SQL Injection (Error-based)
  URL     : https://site.com/page.php?id=1
  Param   : id
  Payload : '
  Evidence: Error signature: 'you have an error in your sql'

[+] Found 1 SQLi vulnerability(ies).
```

---

## Report Formats

| Format | Description |
|---|---|
| `txt` | Plain text — one finding per block |
| `json` | Machine-readable — includes severity summary and session metadata |
| `html` | Styled dark-theme table — severity badges, evidence column |

---

## Repository Structure

```
VXSN/
├── vxsn.py               # Interactive shell entry point
├── vxsn.sh               # Bash launcher
├── modules/
│   ├── base.py           # Abstract base class
│   ├── sqli.py           # SQL Injection module
│   ├── xss.py            # XSS module
│   ├── lfi.py            # LFI module
│   ├── redirect.py       # Open Redirect module
│   ├── misconfig.py      # Misconfiguration module
│   └── report_gen.py     # Report generator
└── utils/
    ├── colors.py         # Terminal color and UI system
    ├── session.py        # Session state manager
    └── http_client.py    # Shared HTTP client
```

---

## Legal

For use only on systems you own or have explicit written authorization to test.
Unauthorized use against third-party systems is illegal.
