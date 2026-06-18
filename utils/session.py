#!/usr/bin/env python3
# utils/session.py — Session state manager for VXSN

import uuid
from datetime import datetime


class Session:

    def __init__(self):
        self._id       = str(uuid.uuid4())[:8].upper()
        self._started  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._findings: dict = {}
        self._history:  list = []
        self._reports:  int  = 0
        self._scans:    int  = 0

    def add_findings(self, module: str, findings: list):
        if module not in self._findings:
            self._findings[module] = []
        self._findings[module].extend(findings)
        self._scans += 1
        target = findings[0].get("url", "—") if findings else "—"
        self._history.append({
            "module": module,
            "target": target,
            "count":  len(findings),
            "time":   datetime.now().strftime("%H:%M:%S"),
        })

    def get_all_findings(self) -> dict:
        return dict(self._findings)

    def get_history(self) -> list:
        return list(self._history)

    def increment_reports(self):
        self._reports += 1

    def get_stats(self) -> dict:
        total_findings = sum(len(v) for v in self._findings.values())
        return {
            "id":       self._id,
            "started":  self._started,
            "scans":    self._scans,
            "findings": total_findings,
            "reports":  self._reports,
        }
