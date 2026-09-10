#!/data/data/com.termux/files/usr/bin/bash
# termux-vapt one-liner installer — fresh Termux
# Usage: curl -fsSL https://yashas-13.github.io/termux-vapt/install.sh | bash
set -euo pipefail
P="${PREFIX:-/data/data/com.termux/files/usr}"
SRC="$P/etc/apt/sources.list.d/termux-vapt.list"
URL="https://yashas-13.github.io/termux-vapt"
echo "[*] termux-vapt installer — $URL"
mkdir -p "$(dirname "$SRC")"
echo "deb [trusted=yes] $URL stable main" > "$SRC"
echo "[*] apt update…"
apt update -y
echo "[*] pkg install termux-vapt…"
pkg install -y termux-vapt || {
  echo "[!] apt install failed — trying direct .deb fallback…"
  TMP="$P/tmp/termux-vapt.deb"
  curl -fsSL "$URL/pool/main/t/termux-vapt/termux-vapt_0.1.0_all.deb" -o "$TMP"
  dpkg -i "$TMP" || apt --fix-broken install -y
}
echo "[*] verify…"
command -v termux-vapt >/dev/null && termux-vapt --help | head -n 5
termux-vapt check || true
echo "[✓] termux-vapt installed. Run: termux-vapt --help"
