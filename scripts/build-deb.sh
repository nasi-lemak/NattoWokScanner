#!/bin/sh
# Builds a .deb package for Debian, Ubuntu and their relatives into dist/.
# It installs the `nattowok` command and an app-menu entry that opens the
# dashboard.
#
#   scripts/build-deb.sh                              # x86-64, static (any distribution)
#   scripts/build-deb.sh aarch64-unknown-linux-musl   # 64-bit ARM (e.g. Raspberry Pi 4/5)
#
# Static (musl) targets need `rustup target add <target>` and a C compiler
# for the TLS library; clang works for x86-64 and is used when available.
# Set DEB_MAINTAINER to put your name and email in the package.
set -eu
cd "$(dirname "$0")/.."

target="${1:-x86_64-unknown-linux-musl}"
case "$target" in
    x86_64-*) arch=amd64 ;;
    aarch64-*) arch=arm64 ;;
    *) echo "unsupported target: $target (use an x86_64 or aarch64 Linux target)" >&2; exit 1 ;;
esac
cc_var="CC_$(echo "$target" | tr '-' '_')"
if [ "$target" = x86_64-unknown-linux-musl ] && [ -z "$(printenv "$cc_var" || true)" ] && command -v clang >/dev/null 2>&1; then
    export "$cc_var=clang"
fi

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
maintainer="${DEB_MAINTAINER:-NattoWok Scanner contributors}"

echo "==> Building $target"
cargo build --release --locked --target "$target"

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
chmod 755 "$root"
install -Dm755 "target/$target/release/nattowok" "$root/usr/bin/nattowok"
install -Dm644 packaging/linux/nattowok.desktop "$root/usr/share/applications/nattowok.desktop"
install -Dm644 web/icon.svg "$root/usr/share/icons/hicolor/scalable/apps/nattowok.svg"
install -Dm644 README.md "$root/usr/share/doc/nattowok/README.md"
{
    echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
    echo "Upstream-Name: nattowok"
    echo
    echo "Files: *"
    echo "License: MIT"
    sed 's/^$/./; s/^/ /' LICENSE
} > "$root/copyright"
install -Dm644 "$root/copyright" "$root/usr/share/doc/nattowok/copyright"
rm "$root/copyright"

mkdir -p "$root/DEBIAN"
size=$(du -sk "$root/usr" | cut -f1)
cat > "$root/DEBIAN/control" <<CONTROL
Package: nattowok
Version: $version
Architecture: $arch
Maintainer: $maintainer
Installed-Size: $size
Section: net
Priority: optional
Recommends: iputils-ping, libnotify-bin
Suggests: network-manager
Description: network scanner that explains what it finds
 NattoWok finds the devices on your network and explains what each one is,
 gives plain-language security advice, diagnoses slow or broken internet,
 logs outages, checks Wi-Fi room by room and can check a rental for hidden
 cameras. Everything runs on your computer; nothing is uploaded.
 .
 Open "NattoWok Scanner" from the app menu, or run "nattowok" in a terminal.
CONTROL

mkdir -p dist
out="dist/nattowok_${version}_${arch}.deb"
dpkg-deb --build --root-owner-group "$root" "$out" >/dev/null
echo "==> $out"
