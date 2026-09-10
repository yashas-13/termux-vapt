#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
cd "$(dirname "$0")"/..
ROOT="$PWD"
REPO="$ROOT/repo"
DEB_DIR="$ROOT/packaging/deb"

echo "[1/4] Staging packaging data..."
rm -rf "$DEB_DIR/bin" "$DEB_DIR/share"
mkdir -p "$DEB_DIR/bin" "$DEB_DIR/share/termux-vapt" "$DEB_DIR/share/doc/termux-vapt" "$DEB_DIR/share/man/man1" "$DEB_DIR/share/bash-completion/completions"
cp -a src/termux_vapt/__init__.py src/termux_vapt/auth.py \
   src/termux_vapt/scan.py src/termux_vapt/vuln.py src/termux_vapt/report.py \
   src/termux_vapt/cli.py \
   src/termux_vapt/templates/ "$DEB_DIR/share/termux-vapt/"

echo "[2/4] Copying wrapper..."
cp src/termux-vapt "$DEB_DIR/bin/"
chmod 755 "$DEB_DIR/bin/termux-vapt"

echo "[3/4] Copying docs + completion..."
cp docs/README.md docs/AUTHORIZATION.md docs/INSTALL.md "$DEB_DIR/share/doc/termux-vapt/"
cp docs/termux-vapt.1 "$DEB_DIR/share/man/man1/"
cp packaging/data/usr/share/bash-completion/completions/termux-vapt "$DEB_DIR/share/bash-completion/completions/" 2>/dev/null || true

echo "[4/4] Building .deb..."
chmod 755 "$DEB_DIR/DEBIAN" "$DEB_DIR/DEBIAN/postinst" "$DEB_DIR/DEBIAN/prerm" "$DEB_DIR/DEBIAN/control" "$DEB_DIR/DEBIAN/conffiles" 2>/dev/null || true
mkdir -p "$REPO/pool/main/t/termux-vapt"
dpkg-deb --build "$DEB_DIR" "$REPO/pool/main/t/termux-vapt/termux-vapt_0.1.0_all.deb"

ls -lh "$REPO/pool/main/t/termux-vapt/"
dpkg-deb -I "$REPO/pool/main/t/termux-vapt/termux-vapt_0.1.0_all.deb"
