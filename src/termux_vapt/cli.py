"""termux-vapt CLI — 5-phase VAPT pipeline with auth gate."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import sys
import urllib.request
from pathlib import Path

from .auth import dump, validate
from . import scan
from . import vuln
from . import report

APP = "termux-vapt"
VERSION = "0.1.0"


def _prefix() -> Path:
    return Path(os.getenv("PREFIX", "/data/data/com.termux/files/usr"))


def _outdir(out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    for sub in ("phase1-recon", "phase2-scan", "phase3-vuln",
                "phase4-exploit", "poc-full"):
        (out / sub).mkdir(exist_ok=True)
    return out


def cmd_check(args: argparse.Namespace) -> int:
    t = scan.check_tools()
    print("Tool availability:")
    for k, v in t.items():
        print(f"  {k}  {'✅' if v else '❌'}")
    ok = all(t[x] for x in ("nmap", "ffuf", "sqlmap", "python3"))
    print("nuclei/httpx"
          " are optional — python fallback used if missing/SIGSYS.")
    # Exploits check
    try:
        from .exploits import list_exploits
        ex = list_exploits()
        print(f"Exploits: {len(ex)} CVEs installed")
        for m in ex[:5]:
            print(f"  {m.get('id')}  {m.get('name')}")
    except Exception as e:
        print(f"Exploits: unavailable ({type(e).__name__})")
    return 0 if ok else 1


def cmd_auth(args: argparse.Namespace) -> int:
    auth = {"target": args.target or "unknown"}
    if args.auth_file:
        p = Path(args.auth_file)
        if not p.exists():
            sys.stderr.write(f"[!] auth file not found: {p}\n")
            return 2
        auth.update(json.loads(p.read_text()))
    auth["scope"] = args.scope or "in-bounds"
    auth["roe"] = args.roe or "read-only"
    auth["safe-word"] = args.safe_word or "STOP"
    out = Path(args.output or "output")
    dump(auth, out)
    print(f"[+] auth written to {out / 'auth.json'}")
    print(f"    target={auth['target']} scope={auth['scope']}")
    return 0


def _read_auth(outdir: Path, force: bool) -> dict:
    candidate = outdir / "auth.json"
    if candidate.exists():
        return json.loads(candidate.read_text())
    # fallback to user home
    fallback = Path.home() / "termux-vapt-auth.json"
    if fallback.exists():
        return json.loads(fallback.read_text())
    return validate(None, interactive=True, force=force)


def _run_phase(target: str, phase: int, outdir: Path, fast: bool) -> list[dict]:
    findings: list[dict] = []
    if phase == 1:
        (outdir / "phase1-recon").mkdir(parents=True, exist_ok=True)
        print(f"[*] Phase 1 recon: {target}")
        # nuclei skipped on Termux if SIGSYS — python fallback
        out_n = outdir / "phase1-recon"
        if scan.nuclei_scan(target, out_n):
            print("    nuclei scan complete")
        else:
            print("    nuclei unavailable/SIGSYS — using python probes")
        # probe live hosts via python
        try:
            req = urllib.request.Request(target)
            urllib.request.urlopen(req, timeout=10)
            live = out_n / "live.txt"
            live.write_text(f"{target}: alive\n")
        except Exception:
            pass
    elif phase == 2:
        (outdir / "phase2-scan").mkdir(parents=True, exist_ok=True)
        print(f"[*] Phase 2 scan: {target}")
        scan.nmap_scan(target, outdir / "phase2-scan", fast=fast)
        scan.ffuf_scan(target, outdir / "phase2-scan")
    elif phase == 3:
        (outdir / "phase3-vuln").mkdir(parents=True, exist_ok=True)
        print(f"[*] Phase 3 vuln: {target}")
        if not fast:
            scan.sqlmap_scan(target, outdir / "phase3-vuln")
        findings = vuln.run_probes(target, outdir / "phase3-vuln")
    elif phase == 4:
        (outdir / "phase4-exploit").mkdir(parents=True, exist_ok=True)
        print(f"[*] Phase 4 exploit (limited): {target}")
    else:
        return []
    return findings


def cmd_scan(args: argparse.Namespace) -> int:
    target = args.target
    phases = args.phase or [1, 2, 3, 4, 5]
    outdir = Path(args.output)
    _outdir(outdir)

    # auth gate
    if not args.force and 1 in phases:
        _read_auth(outdir, force=False)

    for ph in phases:
        if ph == 5:
            print("[*] Phase 5 reporting...")
            report.regenerate(outdir, target=target)
            continue
        findings = _run_phase(target, ph, outdir, fast=args.fast)
        if findings:
            jl = outdir / f"phase{ph}-vuln" / "findings.jsonl"
            jl.write_text("\n".join(json.dumps(f) for f in findings))
    return 0


def cmd_full(args: argparse.Namespace) -> int:
    ns = argparse.Namespace(target=args.target, phase=[1, 2, 3, 4, 5],
                            fast=args.fast, no_exploit=args.no_exploit,
                            output=args.output, force=args.force)
    return cmd_scan(ns)



def cmd_exploit(args: argparse.Namespace) -> int:
    from .exploits import list_exploits, run_check, run_all
    if args.list:
        ex = list_exploits()
        print(f"CVE exploits: {len(ex)} installed")
        for m in ex:
            print(f"  {m.get('id'):16} {m.get('severity', ''):9} {m.get('name')}")
        return 0
    outdir = Path(args.output)
    _outdir(outdir)
    eout = outdir / "phase4-exploit"
    eout.mkdir(parents=True, exist_ok=True)
    if args.cve:
        f = run_check(args.cve, args.target, eout)
        print(json.dumps(f or {"status": "Not Found"}, indent=2))
        if f:
            (eout / f"{args.cve}.jsonl").write_text(json.dumps(f, ensure_ascii=False) + "\n")
        return 0
    findings = run_all(args.target, eout)
    print(f"Exploits ran: {len(findings)} findings")
    for f in findings:
        print(f"  {f.get('id', f.get('name',''))}: {f.get('status')}")
    if findings:
        (eout / "findings.jsonl").write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in findings))
    return 0

def cmd_report(args: argparse.Namespace) -> int:
    report.regenerate(Path(args.output), target=args.target or "output")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=APP, description="Termux VAPT CLI")
    p.add_argument("--version", action="version", version=f"{APP} {VERSION}")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("check")
    sp.set_defaults(func=cmd_check)

    se = sub.add_parser("exploit")
    se.add_argument("target", help="target URL (https://host:port/)")
    se.add_argument("--cve", help="specific CVE id (e.g. CVE-2021-44228)")
    se.add_argument("--list", action="store_true", help="list installed CVE scripts")
    se.add_argument("--output", type=Path, default=Path("output"))
    se.set_defaults(func=cmd_exploit)

    sa = sub.add_parser("auth")
    sa.add_argument("--target")
    sa.add_argument("--scope")
    sa.add_argument("--roe")
    sa.add_argument("--safe-word")
    sa.add_argument("--auth-file", type=Path)
    sa.add_argument("--output", type=Path, default=Path("output"))
    sa.set_defaults(func=cmd_auth)

    ss = sub.add_parser("scan")
    ss.add_argument("target")
    ss.add_argument("--phase", type=int, action="append")
    ss.add_argument("--no-exploit", action="store_true")
    ss.add_argument("--fast", action="store_true")
    ss.add_argument("--output", type=Path, default=Path("output"))
    ss.add_argument("--force", action="store_true")
    ss.set_defaults(func=cmd_scan)

    sf = sub.add_parser("full")
    sf.add_argument("target")
    sf.add_argument("--no-exploit", action="store_true")
    sf.add_argument("--fast", action="store_true")
    sf.add_argument("--output", type=Path, default=Path("output"))
    sf.add_argument("--force", action="store_true")
    sf.set_defaults(func=cmd_full)

    sr = sub.add_parser("report")
    sr.add_argument("output", type=Path)
    sr.add_argument("--target")
    sr.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())