# INSTALL.md — termux-vapt

termux-vapt installs via the Termux apt package system. Two paths: **repo install** (recommended) or **manual .deb**.

## Prerequisites

- Termux on Android (arm64/aarch64)
- `pkg` (apt) available
- At least ~50 MB disk

## 1. Repo Install (recommended)

```bash
# Add repo source — replace USER with your hosting username (e.g. GitHub Pages)
echo 'deb [trusted=yes] https://USER.github.io/termux-vapt stable main' \
  > $PREFIX/etc/apt/sources.list.d/termux-vapt.list

# Update package index
apt update

# Install
pkg install termux-vapt
```

## 2. Manual .deb Install

```bash
# After building (packaging/build.sh) or downloading termux-vapt_0.1.0_all.deb:
dpkg -i repo/pool/main/t/termux-vapt/termux-vapt_0.1.0_all.deb
apt --fix-broken install   # if missing deps
```

## 3. Verify

```bash
termux-vapt check
# expected: nmap ✅ ffuf ✅ sqlmap ✅ python3 ✅
termux-vapt --version
```

## 4. Uninstall

```bash
pkg remove termux-vapt
# and remove the source file
rm $PREFIX/etc/apt/sources.list.d/termux-vapt.list
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `nuclei` SIGSYS crash | Known Android seccomp issue with Go binaries. Run phases with python fallback: `termux-vapt scan <target> --phase 1 --no-exploit` — tool_manager python probes engage. |
| `Depends: python3-bs4` not found | Use pip: `pip install beautifulsoup4`, or control uses `python3-beautifulsoup4` alias. |
| No output dir | Ensure `--output` is absolute and writable (Termux $HOME allowed). |

## Build from source (dev)

```bash
cd ~/termux-vapt
bash packaging/build.sh   # builds .deb into repo/pool/
bash repo/generate.sh     # regenerates Packages.gz + Release
```