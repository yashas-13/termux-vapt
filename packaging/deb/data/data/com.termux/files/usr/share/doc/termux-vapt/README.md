# termux-vapt documentation

## README.md

# termux-vapt — Termux VAPT CLI

**One-line pitch:** A Termux-native CLI that runs a 5-phase vulnerability assessment pipeline with PoC artifacts, HTML/Markdown reports, and strict authorization gates.

## Quickstart

```bash
# Install via package (after repo setup)
pkg install termux-vapt

# Or manually from source
cd ~/termux-vapt
chmod +x src/termux-vapt/termux-vapt
./src/termux-vapt --help
```

## Authorization Gate (MUST READ)

**This tool will NOT run without explicit authorization.** Always confirm:

- ✅ Target scope (hostnames/IP ranges/URLs) is defined
- ✅ Written authorization/engagement letter exists
- ✅ Rules of Engagement (time window, non-destructive)
- ✅ Safe-word/stop condition defined
- ✅ Confirmation dialog or auth file before scanning

## Usage

### Check tool availability
```bash
termux-vapt check
```

### Set authorization (file-based)
```bash
cat > auth.json <<EOF
{
  "target": "https://example.com",
  "scope": "in-bounds",
  "authorization": "signed letter",
  "roe": "2026-01-01 to 2026-01-02",
  "safe-word": "STOP"
}
EOF
```

### Run scan with authorization
```bash
termux-vapt scan https://target.example.com --phase 1 --phase 2 --no-exploit --output output
```

### Run full pipeline
```bash
termux-vapt full https://target.example.com --output output
```

### Verify installation
```bash
termux-vapt check
```

## Output Structure

```
output/
├── phase1-recon/
│   ├── assets.txt
│   ├── live.txt
│   └── findings.jsonl
├── phase2-scan/
│   ├── nmap_vuln.xml
│   ├── ffuf/
│   └── findings.jsonl
├── phase3-vuln/
│   ├── sqlmap/
│   └── findings.jsonl
├── phase4-exploit/
│   └── poc-full/
│   └── poc-<host>-<port>-<name>.txt
├── report.html
├── report.md
└── exec-summary.md
```

## Tool Compatibility

| Tool | Required? | Notes |
|------|-----------|-------|
| nmap | ✅ | Core vulnerability scanner |
| ffuf | ✅ | Directory/file fuzzing |
| sqlmap | ✅ | SQL injection detection |
| nuclei | ⚠️ | Template-based scanning (may SIGSYS on Termux) |
| httpx | ⚠️ | HTTP probing (use python fallback if binary fails) |
| apktool | ✅ | APK reverse engineering |
| adb | ✅ | Mobile device communication |

## License

MIT License © 2026 termux-vapt contributors