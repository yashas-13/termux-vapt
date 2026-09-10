"""Authorization gate for termux-vapt."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REQUIRED_KEYS = ("target", "authorization")


def validate(auth_path: Path | None, interactive: bool = True, force: bool = False) -> dict:
    """Validate authorization gate.

    Returns dict with auth data. Exits non-zero if gate not satisfied unless force.
    """
    data: dict = {}

    if auth_path and auth_path.exists():
        data = json.loads(auth_path.read_text())
    elif auth_path and not auth_path.exists():
        sys.stderr.write(f"[!] auth file not found: {auth_path}\n")
        if force:
            sys.stderr.write("    --force set, continuing with warning.\n")
            return {"target": "unknown", "scope": "unchecked", "force": True}
        sys.exit(2)

    # Auto-persist via prompt if no file
    if not auth_path or not auth_path.exists():
        if force:
            sys.stderr.write("[!] no auth file, --force set, continuing.\n")
            return {"target": "unknown", "force": True}
        if interactive and sys.stdin.isatty():
            sys.stderr.write("[?] confirm you have written authorization for target? [y/N] ")
            ans = input().strip().lower()
            if ans not in ("y", "yes"):
                sys.stderr.write("[!] Refusing to run without authorization.\n")
                sys.exit(2)
            data = {"target": "cli-confirmed", "authorization": "interactive-confirmation"}
        else:
            sys.stderr.write("[!] Authorization required. Pass --auth <file> or run interactively.\n")
            sys.exit(2)

    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing and not force:
        sys.stderr.write(f"[!] auth file missing keys: {missing}\n")
        sys.exit(2)

    return data


def dump(auth: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "auth.json").write_text(json.dumps(auth, indent=2))
