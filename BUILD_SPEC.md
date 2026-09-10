# termux-vapt — Termux Package Repo Release

## Package
- Name: termux-vapt
- Version: 0.1.0
- Architecture: all (python), with aarch64 binary deps declared
- Repo: hosted apt repo (gh-pages branch or raw distribution)
- Install: `pkg install termux-vapt` after adding repo source

## Dependencies
```
Depends: python3 (>= 3.10), nmap, ffuf, sqlmap, python3-pip,
         apksigner (optional: adb, apktool for mobile),
         openjdk-17 (optional: jadx)
Recommends: nikto, thc-hydra, radare2, jadx
```

## Sources bundled
- pentx scripts (5-phase orchestrator) + patches for Termux seccomp (nuclei fallback)
- CLI entrypoint: /data/data/com.termux/files/usr/bin/termux-vapt
- manpage, completion, tools_check wrapper

## Repo hosting
- apt source file: $PREFIX/etc/apt/sources.list.d/termux-vapt.list
- deb built with dpkg-deb, index with dpkg-scanpackages
- Distributed via GitHub Pages (static apt repo)

## Build steps
1. CLI + phases  (src/termux_vapt/*.py)
2. Packaging    (packaging/control, postinst, prerm, manpage)
3. Repo index   (repo/ + Packages.gz + Release)
