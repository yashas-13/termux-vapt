#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
cd "$(dirname "$0")"/..
ROOT="$PWD"
REPO="$ROOT/repo"
DEB_DIR="$ROOT/packaging/deb"

echo "[1/4] Staging packaging data..."
rm -rf "$DEB_DIR/data/usr/share/termux-vapt"
mkdir -p "$DEB_DIR/data/usr/share/termux-vapt"
# Only copy CLI core (native tool usage)
cp -a src/termux_vapt/__init__.py src/termux_vapt/auth.py \
   src/termux_vapt/scan.py src/termux_vapt/vuln.py src/termux_vapt/report.py \
   src/termux_vapt/cli.py \
   src/termux_vapt/templates/ "$DEB_DIR/data/usr/share/termux-vapt/"

echo "[2/4] Copying wrapper..."
mkdir -p "$DEB_DIR/data/usr/bin"
cp src/termux-vapt "$DEB_DIR/data/usr/bin/"
chmod 755 "$DEB_DIR/data/usr/bin/termux-vapt"

echo "[3/4] Copying docs..."
mkdir -p "$DEB_DIR/data/usr/share/doc/termux-vapt" "$DEB_DIR/data/usr/share/man/man1"
cp docs/README.md docs/AUTHORIZATION.md docs/INSTALL.md \
   "$DEB_DIR/data/usr/share/doc/termux-vapt/"
cp docs/termux-vapt.1 "$DEB_DIR/data/usr/share/man/man1/"

echo "[4/4] Building .deb..."
mkdir -p "$REPO/pool/main/t/termux-vapt"
# Use simplified control file
dpkg-deb --build "$DEB_DIR" \
   "$REPO/pool/main/t/termux-vapt/termux-vapt_0.1.0_all.deb"

ls -lh "$REPO/pool/main/t/termux-vapt/"
dpkg-deb -I "$REPO/pool/main/t/termux-vapt/termux-vapt_0.1.0_all.deb"
