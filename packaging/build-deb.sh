#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-$(tr -d '[:space:]' < VERSION)}"
ARCH="${2:-amd64}"
PKG="nexvary-panel"
ROOT="$(pwd)"
OUT="${ROOT}/dist"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$OUT" "$STAGE/DEBIAN" "$STAGE/usr/share/nexvary-panel/source"
tar --exclude=.git --exclude=dist --exclude='*.deb' -cf - . | tar -xf - -C "$STAGE/usr/share/nexvary-panel/source"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Maintainer: NEXVARY <info@nexvary.com>
Homepage: https://nexvary.com/
Depends: bash, curl, ca-certificates, systemd
Description: Nexvary Panel secure hosting and server management control panel
 Nexvary Panel provides graphical hosting, maintenance, security, database,
 mail, SFTP, DNS, SSL, backup and application operations with constrained
 privileged-agent boundaries.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/usr/bin/env bash
set -e
cd /usr/share/nexvary-panel/source
bash installer/install-0.9.sh
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/usr/bin/env bash
set -e
if [ "$1" = remove ]; then
  systemctl stop nexvary-panel 2>/dev/null || true
fi
EOF
chmod 0755 "$STAGE/DEBIAN/prerm"

dpkg-deb --root-owner-group --build "$STAGE" "$OUT/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --info "$OUT/${PKG}_${VERSION}_${ARCH}.deb"
echo "$OUT/${PKG}_${VERSION}_${ARCH}.deb"
