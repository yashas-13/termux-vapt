"""Report generator for termux-vapt."""

from __future__ import annotations

import json
import glob
import os
import time
from pathlib import Path
from string import Template


def merge_findings(phase_dirs: list[Path]) -> list[dict]:
    by_key: dict[str, dict] = {}
    for d in phase_dirs:
        j = d / "findings.jsonl"
        if not j.exists():
            continue
        for line in j.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            f = json.loads(line)
            key = f"{f.get('host','')}:{f.get('port','')}:{f.get('category','')}:{f.get('name','')}"
            # Confirmed wins over Potential
            cur = by_key.get(key)
            if not cur or (cur.get("status") != "Confirmed" and f.get("status") == "Confirmed"):
                by_key[key] = f
    return list(by_key.values())


def write_report(findings: list[dict], outdir: Path, *,
               target: str, date: str, assessor: str = "termux-vapt",
               p1_status: str = "✅", p2_status: str = "✅",
               p3_status: str = "✅", p4_status: str = "✅", p5_status: str = "✅") -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = str(f.get("severity", "")).lower()
        if s in counts:
            counts[s] += 1
    total = len(findings)

    # Persist merged findings
    (outdir / "findings-merged.json").write_text(json.dumps(findings, indent=2))
    (outdir / "findings-merged.jsonl").write_text(
        "\n".join(json.dumps(f, ensure_ascii=False) for f in findings)
    )

    # Persist exec summary (markdown)
    (outdir / "exec-summary.md").write_text(
        f"# Exec Summary — {target}\n\n"
        f"Critical={counts['critical']} High={counts['high']} Medium={counts['medium']} Low={counts['low']} Info={counts['info']} Total={total}\n"
    )

    # Persist full markdown report (stub)
    (outdir / "report.md").write_text(
        f"# VAPT Report — {target}\n\n"
        f"Date: {date}\nAssessor: {assessor}\n\n"
        + "\n".join(
            f"## {f.get('name','')} ({f.get('severity','')})\n"
            f"{f.get('description','')}\n\nEvidence:\n```\n{f.get('evidence','')}\n```\n"
            f"Remediation: {f.get('remediation','')}\n"
            for f in findings
        )
        or "*No findings.*\n"
    )

    # Write per-finding PoC files
    pocd = outdir / "poc-full"
    pocd.mkdir(exist_ok=True)
    for f in findings:
        host = f.get("host", "unknown")
        port = f.get("port", "unknown")
        name = "".join(c if c.isalnum() else "-" for c in str(f.get("name", "finding")))
        fname = f"poc-{host}-{port}-{name}.txt"
        (pocd / fname).write_text(
            f"Finding: {f.get('name','')} [{f.get('severity','')}]\n"
            f"Category: {f.get('category','')}\n"
            f"Endpoint: {f.get('endpoint','')}\n\n"
            f"Request:\n{f.get('poc_request','')}\n\n"
            f"Response:\n{f.get('poc_response','')}\n\n"
            f"Impact: {f.get('impact','')}\nRemediation: {f.get('remediation','')}\n"
        )

    # HTML report via template
    try:
        from termux_vapt.templates import render_report
        html = render_report({
            "target": target,
            "date": date,
            "assessor": assessor,
            "scope": target,
            "targets": target,
            "authorization": "Provided",
            "duration": date,
            "constraints": "No destructive payloads",
            "executive_summary": f"{total} findings.",
            "p1_status": p1_status,
            "p2_status": p2_status,
            "p3_status": p3_status,
            "p4_status": p4_status,
            "p5_status": p5_status,
            "findings": findings,
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "info": counts["info"],
            "total": total,
            "version": "0.1.0",
        })
        (outdir / "report.html").write_text(html)
    except Exception as e:
        (outdir / "report.html").write_text(f"<pre>render failed: {e}</pre>")


def regenerate(outdir: Path, target: str | None = None) -> None:
    phases = [outdir / f"phase{i}" for i in (1, 2, 3, 4)]
    phase_paths = [p for p in phases if p.exists()]
    merged = merge_findings(phase_paths)
    write_report(merged, outdir, target=target or "output",
               date=time.strftime("%Y-%m-%d"), assessor=os.getenv("USER", "termux-vapt"))
