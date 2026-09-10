"""Vulnerability assessment probes for termux-vapt."""

from __future__ import annotations

import json
import ssl
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable


def _req(url: str, *, payload: str | None = None, headers: dict[str, str] | None = None,
         timeout: int = 15) -> tuple[str, str, str]:
    req = urllib.request.Request(url, data=payload.encode() if payload else None,
                                headers=headers or {})
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", errors="replace")
            return r.get_method(), str(r.status), body
    except Exception as e:
        return "ERR", str(type(e).__name__), str(e)


def _write_poc(directory: Path, finding: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "poc.txt").write_text(
        f"Host: {finding.get('host')}\nPort: {finding.get('port')}\n"
        f"Request:\n{finding.get('poc_request','')}\n"
        f"Response:\n{finding.get('poc_response','')}\n"
    )


def check_security_headers(target: str, outdir: Path) -> list[dict]:
    findings: list[dict] = []
    _, status, _ = _req(target)
    required = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
                "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"]
    missing = [h for h in required if h not in _]
    if missing:
        f = {
            "host": urllib.parse.urlparse(target).hostname or "",
            "port": str(urllib.parse.urlparse(target).port or 443),
            "category": "headers",
            "name": "Missing Security Headers",
            "severity": "Low",
            "status": "Confirmed",
            "cvss": "3.7",
            "cwe": "CWE-693",
            "endpoint": target,
            "description": f"Missing headers: {', '.join(missing)}",
            "evidence": f"HTTP {status}",
            "poc_request": f"GET {target} HTTP/1.1\r\nHost: {urllib.parse.urlparse(target).hostname}\r\n",
            "poc_response": f"HTTP/{status}\r\n...missing: {missing}",
            "impact": "Reduced defense-in-depth against clickjacking, MIME-sniffing, and downgrade.",
            "remediation": "Add missing headers with sane defaults.",
        }
        _write_poc(outdir / "poc-headers", f)
        findings.append(f)
    return findings


def check_tls_weak(target: str, outdir: Path) -> list[dict]:
    findings: list[dict] = []
    host = urllib.parse.urlparse(target).hostname
    port = urllib.parse.urlparse(target).port or 443
    if not host:
        return findings
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ssl.create_connection((host, port), timeout=8, context=ctx) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                ver = ss.version()
                if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                    f = {
                        "host": host, "port": str(port), "category": "tls",
                        "name": "Weak TLS Version", "severity": "High",
                        "status": "Confirmed", "cvss": "7.4", "cwe": "CWE-327",
                        "endpoint": f"{target}:{port}",
                        "description": f"Server negotiated {ver}",
                        "evidence": f"version={ver} cipher={ss.cipher()[0]}",
                        "poc_request": f"openssl s_client -connect {host}:{port} -{ver} </dev/null 2>&1",
                        "poc_response": f"CONNECTED({ver})",
                        "impact": "Man-in-the-middle downgrade to recover plaintext.",
                        "remediation": "Disable TLSv1/TLSv1.1, require TLSv1.2+ and strong ciphers.",
                    }
                    _write_poc(outdir / "poc-tls", f)
                    findings.append(f)
    except Exception as e:
        pass
    return findings


def check_lfi(target: str, outdir: Path) -> list[dict]:
    findings: list[dict] = []
    payloads = ["../../../../etc/passwd", "....//....//....//....//etc/passwd",
                "/etc/passwd"]
    for p in payloads:
        url = urllib.parse.urljoin(target, "?" + urllib.parse.urlencode({"file": p}))
        try:
            _, status, body = _req(url)
        except Exception:
            continue
        if "root:" in body and ":" in body:
            f = {
                "host": urllib.parse.urlparse(target).hostname or "",
                "port": str(urllib.parse.urlparse(target).port or 80),
                "category": "lfi", "name": "Local File Inclusion",
                "severity": "High", "status": "Confirmed",
                "cvss": "7.5", "cwe": "CWE-22",
                "endpoint": target, "description": f"LFI with payload {p}",
                "evidence": body[:800],
                "poc_request": f"GET {url} HTTP/1.1",
                "poc_response": body[:800],
                "impact": "Remote disclosure of arbitrary filesystem files.",
                "remediation": "Use basename() allowlists, chroot, or virtual filesystem.",
            }
            _write_poc(outdir / "poc-lfi", f)
            findings.append(f)
            break
    return findings


def check_xss_reflection(target: str, outdir: Path) -> list[dict]:
    findings: list[dict] = []
    probe = "<termux-vapt-probe>"
    url = urllib.parse.urljoin(target, "?" + urllib.parse.urlencode({"q": probe}))
    try:
        _, status, body = _req(url)
    except Exception:
        return findings
    if probe in body:
        f = {
            "host": urllib.parse.urlparse(target).hostname or "",
            "port": str(urllib.parse.urlparse(target).port or 80),
            "category": "xss", "name": "Reflected XSS Probe",
            "severity": "Medium", "status": "Potential",
            "cvss": "6.1", "cwe": "CWE-79",
            "endpoint": url, "description": "Parameter reflected without encoding",
            "evidence": body[:800],
            "poc_request": f"GET {url} HTTP/1.1",
            "poc_response": body[:800],
            "impact": "Client-side script execution in victim context.",
            "remediation": "Contextual output encoding + CSP nonce + input validation.",
        }
        _write_poc(outdir / "poc-xss", f)
        findings.append(f)
    return findings


def check_ssrf_hints(target: str, outdir: Path) -> list[dict]:
    findings: list[dict] = []
    internal = "http://127.0.0.1:22"
    url = urllib.parse.urljoin(target, "?" + urllib.parse.urlencode({"url": internal}))
    try:
        _, status, body = _req(url, timeout=10)
    except Exception:
        return findings
    if any(tok in body for tok in ("SSH-2.0-OpenSSH", "220 ", "Escape character")):
        f = {
            "host": urllib.parse.urlparse(target).hostname or "",
            "port": str(urllib.parse.urlparse(target).port or 80),
            "category": "ssrf", "name": "SSRF to Internal Service",
            "severity": "High", "status": "Confirmed",
            "cvss": "9.1", "cwe": "CWE-918",
            "endpoint": url, "description": "Server issued request to internal network",
            "evidence": body[:800],
            "poc_request": f"GET {url} HTTP/1.1",
            "poc_response": body[:800],
            "impact": "Bypass network segmentation, access internal metadata/SSH/REDIS.",
            "remediation": "Allowlist hostnames/IPs, deny RFC1918 responses, block private IPs.",
        }
        _write_poc(outdir / "poc-ssrf", f)
        findings.append(f)
    return findings


def run_probes(target: str, outdir: Path) -> list[dict]:
    findings: list[dict] = []
    findings.extend(check_security_headers(target, outdir))
    findings.extend(check_tls_weak(target, outdir))
    findings.extend(check_lfi(target, outdir))
    findings.extend(check_xss_reflection(target, outdir))
    findings.extend(check_ssrf_hints(target, outdir))
    return findings
