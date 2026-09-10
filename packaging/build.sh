#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
cd "$(dirname "$0")"/..
ROOT="$PWD"
REPO="$ROOT/repo"
DEB_DIR="$ROOT/packaging/deb"
PFX="data/data/com.termux/files/usr"

echo "[1/4] Staging python package (site-packages/termux_vapt)..."
PYVER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
SITE="$DEB_DIR/$PFX/lib/python${PYVER}/site-packages/termux_vapt"
RMDEP="$DEB_DIR/$PFX/lib/python3.13/site-packages/termux_vapt"
for d in "$SITE" "$RMDEP"; do
  mkdir -p "$d"
  cp -a src/termux_vapt/__init__.py src/termux_vapt/auth.py \
     src/termux_vapt/scan.py src/termux_vapt/vuln.py src/termux_vapt/report.py \
     src/termux_vapt/cli.py \
     src/termux_vapt/templates/ src/termux_vapt/exploits/ "$d/"
done

echo "[2/4] Wrapper bin/termux-vapt..."
BIN="$DEB_DIR/$PFX/bin/termux-vapt"
mkdir -p "$(dirname "$BIN")"
cp src/termux-vapt "$BIN"
chmod 755 "$BIN"

echo "[3/4] Docs + completion..."
mkdir -p "$DEB_DIR/$PFX/share/doc/termux-vapt" "$DEB_DIR/$PFX/share/man/man1" "$DEB_DIR/$PFX/share/bash-completion/completions"
cp docs/README.md docs/AUTHORIZATION.md docs/INSTALL.md "$DEB_DIR/$PFX/share/doc/termux-vapt/"
cp docs/termux-vapt.1 "$DEB_DIR/$PFX/share/man/man1/"
cp packaging/data/usr/share/bash-completion/completions/termux-vapt "$DEB_DIR/$PFX/share/bash-completion/completions/" 2>/dev/null || true

echo "[4/4] Building .deb..."
chmod 755 "$DEB_DIR/DEBIAN" "$DEB_DIR/DEBIAN/postinst" "$DEB_DIR/DEBIAN/prerm" 2>/dev/null || true
mkdir -p "$REPO/pool/main/t/termux-vapt"
dpkg-deb --build "$DEB_DIR" "$REPO/pool/main/t/termux-vapt/termux-vapt_0.1.0_all.deb"
ls -lh "$REPO/pool/main/t/termux-vapt/"
dpkg-deb -I "$REPO/pool/main/t/termux-vapt/termux-vapt_0.1.0_all.deb"
