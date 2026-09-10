#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
DIST="stable"
COMP="main"
INDEX="dists/$DIST/$COMP/binary-all"

mkdir -p "$INDEX"

# Build Packages index from .deb files
> "$INDEX/Packages"
for deb in pool/main/t/termux-vapt/*.deb; do
    [ -f "$deb" ] || continue
    {
        dpkg-deb -f "$deb" Package
        dpkg-deb -f "$deb" Version
        dpkg-deb -f "$deb" Architecture
        dpkg-deb -f "$deb" Maintainer
        dpkg-deb -f "$deb" Depends
        dpkg-deb -f "$deb" Recommends
        dpkg-deb -f "$deb" Suggests
        dpkg-deb -f "$deb" Description
        dpkg-deb -f "$deb" Installed-Size
        printf "Filename: pool/main/t/termux-vapt/%s\n" "$(basename "$deb")"
        printf "Size: %s\n" "$(stat -c%s "$deb")"
        printf "MD5sum: %s\n" "$(md5sum "$deb" | cut -d' ' -f1)"
        printf "SHA1: %s\n" "$(sha1sum "$deb" | cut -d' ' -f1)"
        printf "SHA256: %s\n" "$(sha256sum "$deb" | cut -d' ' -f1)"
        echo
    } >> "$INDEX/Packages"
done

gzip -kf "$INDEX/Packages"

cat > "$INDEX/Release" <<EOF
Origin: termux-vapt
Label: termux-vapt
Suite: $DIST
Codename: stable
Architectures: all aarch64 arm
Components: $COMP
Description: termux-vapt — VAPT pipeline for Termux
Date: $(date -Ru 2>/dev/null || date '+%a, %d %b %Y %H:%M:%S %z')
EOF

echo "Generated repo index:"
ls -lh "$INDEX/"
