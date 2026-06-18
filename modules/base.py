#!/usr/bin/env python3
# modules/base.py — Abstract base class for all VXSN modules

from abc import ABC, abstractmethod
from utils.colors import Colors, print_table, print_section
from utils.http_client import HTTPClient


class BaseModule(ABC):

    NAME:        str  = "base"
    DESCRIPTION: str  = ""
    AUTHOR:      str  = "NeiveZ"
    SEVERITY:    str  = "HIGH"
    REFERENCES:  list = []

    def __init__(self):
        self.options: dict = {}
        self.client:  HTTPClient = None
        self._define_options()

    @abstractmethod
    def _define_options(self):
        ...

    @abstractmethod
    def run(self) -> list:
        """Execute the scan. Must return list of finding dicts."""
        ...

    # ── Option helpers ────────────────────────────────────────────

    def _add_option(self, name: str, default, required: bool, description: str):
        self.options[name.upper()] = {
            "value":    default,
            "required": required,
            "desc":     description,
        }

    def set_option(self, name: str, value: str) -> bool:
        if name.upper() not in self.options:
            return False
        self.options[name.upper()]["value"] = value
        return True

    def get_option(self, name: str):
        return self.options.get(name.upper(), {}).get("value")

    def _validate(self) -> bool:
        for name, meta in self.options.items():
            if meta["required"] and not meta["value"]:
                from utils.colors import print_status
                print_status(f"Required option not set: {Colors.CYAN}{name}{Colors.RESET}", "error")
                return False
        return True

    def _init_client(self) -> HTTPClient:
        timeout = int(self.get_option("TIMEOUT") or 10)
        delay   = float(self.get_option("DELAY")   or 0)
        return HTTPClient(timeout=timeout, delay=delay)

    # ── Finding builder ───────────────────────────────────────────

    def _finding(self, vuln_type: str, url: str, param: str,
                 payload: str, severity: str = None, evidence: str = "") -> dict:
        return {
            "type":     vuln_type,
            "url":      url,
            "param":    param,
            "payload":  payload,
            "severity": severity or self.SEVERITY,
            "evidence": evidence[:300] if evidence else "",
            "module":   self.NAME,
        }

    # ── Display helpers ───────────────────────────────────────────

    def show_options(self):
        print_section(f"Options — {self.NAME}")
        rows = [
            (
                name,
                str(meta["value"]) if meta["value"] else Colors.DARK_GRAY + "unset" + Colors.RESET,
                "yes" if meta["required"] else "no",
                meta["desc"],
            )
            for name, meta in self.options.items()
        ]
        print_table(["Option", "Value", "Required", "Description"], rows)

    def show_info(self):
        print_section(f"Module — {self.NAME}")
        print(f"  {Colors.DARK_GRAY}Name       {Colors.RESET}: {Colors.WHITE}{self.NAME}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Description{Colors.RESET}: {self.DESCRIPTION}")
        print(f"  {Colors.DARK_GRAY}Author     {Colors.RESET}: {self.AUTHOR}")
        print(f"  {Colors.DARK_GRAY}Severity   {Colors.RESET}: {Colors.RED}{self.SEVERITY}{Colors.RESET}")
        if self.REFERENCES:
            print(f"  {Colors.DARK_GRAY}References {Colors.RESET}:")
            for ref in self.REFERENCES:
                print(f"    {Colors.CYAN}{ref}{Colors.RESET}")
        print()
        self.show_options()
