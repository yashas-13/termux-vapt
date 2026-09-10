#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
DIST="stable"
COMP="main"
INDEX="dists/$DIST/$COMP/binary-all"
mkdir -p "$INDEX"
> "$INDEX/Packages"
for deb in pool/main/t/termux-vapt/*.deb; do
    [ -f "$deb" ] || continue
    {
        echo "Package: $(dpkg-deb -f "$deb" Package)"
        echo "Version: $(dpkg-deb -f "$deb" Version)"
        echo "Architecture: $(dpkg-deb -f "$deb" Architecture)"
        echo "Maintainer: $(dpkg-deb -f "$deb" Maintainer)"
        echo "Depends: $(dpkg-deb -f "$deb" Depends)"
        echo "Recommends: $(dpkg-deb -f "$deb" Recommends)"
        echo "Suggests: $(dpkg-deb -f "$deb" Suggests)"
        echo "Description: $(dpkg-deb -f "$deb" Description)"
        echo "Installed-Size: $(dpkg-deb -f "$deb" Installed-Size 2>/dev/null || echo "0")"
        printf "Filename: pool/main/t/termux-vapt/%s\n" "$(basename "$deb")"
        printf "Size: %s\n" "$(stat -c%s "$deb")"
        printf "MD5sum: %s\n" "$(md5sum "$deb" | cut -d' ' -f1)"
        printf "SHA1: %s\n" "$(sha1sum "$deb" | cut -d' ' -f1)"
        printf "SHA256: %s\n" "$(sha256sum "$deb" | cut -d' ' -f1)"
        echo
    } >> "$INDEX/Packages"
done
gzip -kf "$INDEX/Packages"
mkdir -p "dists/$DIST/$COMP/binary-aarch64"
cp "$INDEX/Packages" "dists/$DIST/$COMP/binary-aarch64/Packages"
cp "$INDEX/Packages.gz" "dists/$DIST/$COMP/binary-aarch64/Packages.gz"
dt="$(date -Ru 2>/dev/null || date '+%a, %d %b %Y %H:%M:%S %z')"
printf "Origin: termux-vapt\nLabel: termux-vapt\nSuite: %s\nCodename: stable\nArchitectures: aarch64\nComponents: %s\nDescription: termux-vapt — VAPT pipeline for Termux (aarch64 mirror)\nDate: %s\n" "$DIST" "$COMP" "$dt" > "dists/$DIST/$COMP/binary-aarch64/Release"
printf "Origin: termux-vapt\nLabel: termux-vapt\nSuite: %s\nCodename: stable\nArchitectures: all\nComponents: %s\nDescription: termux-vapt — VAPT pipeline for Termux\nDate: %s\n" "$DIST" "$COMP" "$dt" > "$INDEX/Release"
echo "Generated repo index:"
ls -lh "$INDEX/"
ls -lh "dists/$DIST/$COMP/binary-aarch64/"
