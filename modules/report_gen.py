#!/usr/bin/env python3
# modules/report_gen.py — Report generator for VXSN

import os
import json
from datetime import datetime
from utils.colors import print_status


class ReportGenerator:

    def __init__(self, findings: dict, session_stats: dict):
        self.findings  = findings
        self.stats     = session_stats
        self.ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.ts_human  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.all_vulns = [f for flist in findings.values() for f in flist]
        os.makedirs("reports", exist_ok=True)

    def generate(self, fmt: str = "html", filename: str = None) -> str | None:
        fmt = fmt.lower()
        if fmt not in ("txt", "json", "html"):
            print_status(f"Unknown format '{fmt}'. Use txt, json, or html.", "error")
            return None
        fname = filename or f"vxsn_report_{self.ts}.{fmt}"
        if not fname.endswith(f".{fmt}"):
            fname += f".{fmt}"
        path = os.path.join("reports", fname)
        content = {"txt": self._txt, "json": self._json, "html": self._html}[fmt]()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    # ── TXT ───────────────────────────────────────────────────────

    def _txt(self) -> str:
        lines = [
            "=" * 60,
            "  VXSN — VULNERABILITY SCAN REPORT",
            "=" * 60,
            f"  Generated : {self.ts_human}",
            f"  Session   : {self.stats['id']}",
            f"  Findings  : {len(self.all_vulns)}",
            "=" * 60, "",
        ]
        for module, flist in self.findings.items():
            lines += [f"[{module}]", "-" * 40]
            for f in flist:
                lines += [
                    f"  [{f.get('severity','?')}] {f.get('type','')}",
                    f"  URL     : {f.get('url','')}",
                    f"  Param   : {f.get('param','')}",
                    f"  Payload : {f.get('payload','')}",
                    f"  Evidence: {f.get('evidence','')}",
                    "",
                ]
        lines += ["=" * 60, "  END OF REPORT", "=" * 60]
        return "\n".join(lines)

    # ── JSON ──────────────────────────────────────────────────────

    def _json(self) -> str:
        return json.dumps({
            "meta": {
                "tool":      "VXSN v1.0",
                "generated": self.ts_human,
                "session":   self.stats,
            },
            "summary": {
                "total":  len(self.all_vulns),
                "high":   sum(1 for f in self.all_vulns if f.get("severity") == "HIGH"),
                "medium": sum(1 for f in self.all_vulns if f.get("severity") == "MEDIUM"),
                "low":    sum(1 for f in self.all_vulns if f.get("severity") == "LOW"),
            },
            "findings": self.findings,
        }, indent=2, default=str)

    # ── HTML ──────────────────────────────────────────────────────

    def _html(self) -> str:
        high   = sum(1 for f in self.all_vulns if f.get("severity") == "HIGH")
        medium = sum(1 for f in self.all_vulns if f.get("severity") == "MEDIUM")
        low    = sum(1 for f in self.all_vulns if f.get("severity") == "LOW")

        rows = ""
        for f in self.all_vulns:
            sev   = f.get("severity", "INFO")
            color = {"HIGH": "#f85149", "MEDIUM": "#e3b341", "LOW": "#79c0ff"}.get(sev, "#8b949e")
            rows += f"""
            <tr>
                <td><span class="badge" style="background:{color}22;color:{color};border:1px solid {color}">{sev}</span></td>
                <td>{f.get('type','')}</td>
                <td class="mono">{f.get('url','')}</td>
                <td class="mono">{f.get('param','')}</td>
                <td class="mono payload">{f.get('payload','')}</td>
                <td class="evidence">{f.get('evidence','')}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VXSN Report — {self.ts_human}</title>
<style>
  :root {{
    --bg:#0d1117;--surface:#161b22;--border:#30363d;
    --red:#f85149;--yellow:#e3b341;--blue:#79c0ff;
    --green:#3fb950;--text:#c9d1d9;--dim:#6e7681;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:2rem}}
  header{{border-bottom:1px solid var(--border);padding-bottom:1.5rem;margin-bottom:2rem}}
  h1{{color:var(--red);font-size:1.5rem;letter-spacing:2px;font-family:monospace}}
  .meta{{color:var(--dim);font-size:.85rem;margin-top:.5rem}}
  .meta span{{color:var(--blue)}}
  .summary{{display:flex;gap:1rem;margin-bottom:2rem}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:1rem 1.5rem;text-align:center}}
  .card-num{{font-size:2rem;font-weight:700}}
  .card-label{{font-size:.75rem;color:var(--dim);text-transform:uppercase;letter-spacing:1px}}
  table{{width:100%;border-collapse:collapse;font-size:.8rem}}
  th{{background:#1c2128;color:var(--dim);padding:.6rem .8rem;text-align:left;border-bottom:1px solid var(--border);font-weight:500}}
  td{{padding:.6rem .8rem;border-bottom:1px solid var(--border);vertical-align:top}}
  .mono{{font-family:monospace;font-size:.75rem;color:var(--blue);word-break:break-all}}
  .payload{{color:var(--yellow)}}
  .evidence{{color:var(--dim);font-size:.75rem}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:600;font-family:monospace}}
  footer{{color:var(--dim);font-size:.75rem;margin-top:3rem;border-top:1px solid var(--border);padding-top:1rem;text-align:center}}
</style>
</head>
<body>
<header>
  <h1>VXSN — VULNERABILITY SCAN REPORT</h1>
  <p class="meta">Generated: <span>{self.ts_human}</span> &nbsp;|&nbsp; Session: <span>{self.stats['id']}</span></p>
</header>
<div class="summary">
  <div class="card"><div class="card-num" style="color:var(--text)">{len(self.all_vulns)}</div><div class="card-label">Total</div></div>
  <div class="card"><div class="card-num" style="color:var(--red)">{high}</div><div class="card-label">High</div></div>
  <div class="card"><div class="card-num" style="color:var(--yellow)">{medium}</div><div class="card-label">Medium</div></div>
  <div class="card"><div class="card-num" style="color:var(--blue)">{low}</div><div class="card-label">Low</div></div>
</div>
<table>
  <thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Param</th><th>Payload</th><th>Evidence</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<footer>VXSN v1.0 — For authorized security testing only | NeiveZ</footer>
</body></html>"""
