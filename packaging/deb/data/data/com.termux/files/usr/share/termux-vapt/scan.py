"""Scan helpers for termux-vapt."""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Sequence

TOOLS = (
    "nmap", "ffuf", "sqlmap", "nuclei", "httpx", "python3",
    "apktool", "adb",
)


def check_tools() -> dict[str, bool]:
    return {tool: bool(shutil.which(tool)) for tool in TOOLS}


def which(tool: str) -> str | None:
    return shutil.which(tool)


def run(cmd: Sequence[str], cwd: Path | None = None, out: Path | None = None,
        timeout: int = 600) -> int:
    """Run a command, stream to out file if given. Returns exit code."""
    try:
        proc = subprocess.run(
            list(cmd),
            cwd=cwd,
            stdout=subprocess.PIPE if out else None,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
        )
        rc = proc.returncode
    except FileNotFoundError:
        sys.stderr.write(f"[!] command not found: {cmd[0]}\n")
        return 127
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"[!] timeout after {timeout}s: {' '.join(cmd)}\n")
        return 124
    # SIGSYS = 31 (Termux seccomp kills Go binaries on faccessat2)
    if rc and abs(rc) in (9, 31, -31):
        sys.stderr.write(f"[!] {cmd[0]} killed by seccomp (SIGSYS) — python fallback will engage\n")
        rc = 125
    if out and proc.stdout:
        out.write_text(proc.stdout)
    return rc


def nmap_scan(target: str, outdir: Path, fast: bool = False) -> Path | None:
    xml = outdir / "nmap_vuln.xml"
    flags = ["-sV", "--script=vuln,auth,exploit,discovery,default", "-oX", str(xml)]
    if fast:
        flags = ["-F", "--top-ports", "100", "-sV", "-oX", str(xml)]
    rc = run(["nmap"] + flags + [target], timeout=900)
    return xml if xml.exists() else None


def ffuf_scan(target: str, outdir: Path, wordlist: str | None = None) -> Path | None:
    out = outdir / "ffuf.txt"
    wl = wordlist or "/data/data/com.termux/files/usr/share/wordlists/dirb/common.txt"
    cmd = [
        "ffuf", "-u", f"{target}/FUZZ",
        "-w", wl, "-mc", "200,301,302,401,403,500",
        "-o", str(out), "-of", "text",
    ]
    run(cmd, timeout=700)
    return out if out.exists() else None


def sqlmap_scan(target: str, outdir: Path) -> Path | None:
    d = outdir / "sqlmap"
    d.mkdir(parents=True, exist_ok=True)
    cmd = [
        "sqlmap", "--batch", "--level", "2", "--risk", "1",
        "--output-dir", str(d), "--url", target,
    ]
    run(cmd, timeout=1200)
    return d


def nuclei_scan(target: str, outdir: Path) -> Path | None:
    out = outdir / "nuclei.txt"
    if not which("nuclei"):
        return None
    cmd = ["nuclei", "-u", target, "-o", str(out), "-silent"]
    rc = run(cmd, timeout=900)
    return out if out.exists() else None
