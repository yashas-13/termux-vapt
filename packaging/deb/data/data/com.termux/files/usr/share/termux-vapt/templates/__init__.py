"""Offline HTML report renderer for termux-vapt."""

import html
from pathlib import Path
from string import Template

__all__ = ["render_report"]

_TEMPLATE = Path(__file__).with_name("report.html").read_text(encoding="utf-8")
_SEVERITIES = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info"}


def render_report(data: dict) -> str:
    """Render findings into the offline HTML report template.

    data: target, date, assessor, scope, targets, authorization, duration,
    constraints, executive_summary, p1_status..p5_status, version, findings[].
    """
    findings = data.get("findings") or []
    cards = []
    for i, finding in enumerate(findings, start=1):
        sev = str(finding.get("severity") or "info").lower()
        cards.append(
            Template(
                """
<div class="card">
<div class="card-h"><h3>{{NAME}} <small style="color:var(--info)">#{ID} · {{CATEGORY}}</small></h3>
<span class="badge badge-{{SLUG}}">{{SEVERITY}} · CVSS {{CVSS}}</span></div>
<div class="card-b">
<dl class="kv"><dt>Endpoint</dt><dd>{{ENDPOINT}}</dd><dt>CWE</dt><dd>{{CWE}}</dd><dt>Status</dt><dd>{{STATUS}}</dd><dt>Host:Port</dt><dd>{{HOST}}:{{PORT}}</dd></dl>
<h4>Description</h4><p style="font-size:13px">{{DESCRIPTION}}</p>
<h4>Evidence</h4><pre>{{EVIDENCE}}</pre>
<h4>Proof of Concept — Request</h4><pre>{{POC_REQUEST}}</pre>
<h4>Proof of Concept — Response (truncated)</h4><pre>{{POC_RESPONSE}}</pre>
<h4>Impact</h4><p style="font-size:13px">{{IMPACT}}</p>
<h4>Remediation</h4><p style="font-size:13px">{{REMEDIATION}}</p>
</div></div>"""
            ).safe_substitute(
                ID=i,
                NAME=html.escape(str(finding.get("name") or "Untitled")),
                CATEGORY=html.escape(str(finding.get("category") or "web")),
                SLUG=_SEVERITIES.get(sev, "info"),
                SEVERITY=html.escape(str(finding.get("severity") or "Info").title()),
                CVSS=html.escape(str(finding.get("cvss") or "N/A")),
                ENDPOINT=html.escape(str(finding.get("endpoint") or finding.get("name") or "")),
                CWE=html.escape(str(finding.get("cwe") or "N/A")),
                STATUS=html.escape(str(finding.get("status") or "Potential")),
                HOST=html.escape(str(finding.get("host") or "")),
                PORT=html.escape(str(finding.get("port") or "")),
                DESCRIPTION=html.escape(str(finding.get("description") or "")),
                EVIDENCE=html.escape(str(finding.get("evidence") or "")),
                POC_REQUEST=html.escape(str(finding.get("poc_request") or "")),
                POC_RESPONSE=html.escape(str(finding.get("poc_response") or "")),
                IMPACT=html.escape(str(finding.get("impact") or "")),
                REMEDIATION=html.escape(str(finding.get("remediation") or "")),
            )
        )

    values = {
        "TARGET": html.escape(str(data.get("target") or "")),
        "DATE": html.escape(str(data.get("date") or "")),
        "ASSESSOR": html.escape(str(data.get("assessor") or "termux-vapt")),
        "SCOPE": html.escape(str(data.get("scope") or "")),
        "CRITICAL": data.get("critical", 0),
        "HIGH": data.get("high", 0),
        "MEDIUM": data.get("medium", 0),
        "LOW": data.get("low", 0),
        "INFO": data.get("info", 0),
        "TOTAL": data.get("total", len(findings)),
        "EXECUTIVE_SUMMARY": html.escape(str(data.get("executive_summary") or "")),
        "TARGETS": html.escape(str(data.get("targets") or data.get("target") or "")),
        "AUTHORIZATION": html.escape(str(data.get("authorization") or "Not recorded")),
        "DURATION": html.escape(str(data.get("duration") or "")),
        "CONSTRAINTS": html.escape(str(data.get("constraints") or "")),
        "P1_STATUS": html.escape(str(data.get("p1_status") or "")),
        "P2_STATUS": html.escape(str(data.get("p2_status") or "")),
        "P3_STATUS": html.escape(str(data.get("p3_status") or "")),
        "P4_STATUS": html.escape(str(data.get("p4_status") or "")),
        "P5_STATUS": html.escape(str(data.get("p5_status") or "")),
        "FINDINGS_HTML": "".join(cards),
        "VERSION": html.escape(str(data.get("version") or "0.1.0")),
    }
    return Template(_TEMPLATE).safe_substitute(values)
