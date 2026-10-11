#!/bin/sh
# Builds release binaries and packages them into dist/ with SHA256SUMS.
#
#   scripts/build-release.sh                       # this computer's platform
#   scripts/build-release.sh x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#
# Extra targets need `rustup target add <target>` plus a C compiler for them
# (the TLS library compiles a little C). A static Linux build that runs on any
# distribution works with clang:
#
#   CC_x86_64_unknown_linux_musl=clang scripts/build-release.sh x86_64-unknown-linux-musl
#
# Building macOS and Windows packages is simplest on a Mac or Windows machine.
set -eu
cd "$(dirname "$0")/.."

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
host=$(rustc -vV | sed -n 's/^host: //p')
targets="${*:-$host}"
mkdir -p dist

for target in $targets; do
    echo "==> Building $target"
    cargo build --release --locked --target "$target"
    exe=nattowok
    case "$target" in *windows*) exe=nattowok.exe ;; esac
    name="nattowok-$version-$target"
    rm -rf "dist/$name"
    mkdir -p "dist/$name"
    cp "target/$target/release/$exe" README.md LICENSE "dist/$name/"
    case "$target" in
        *windows*)
            rm -f "dist/$name.zip"
            if command -v zip >/dev/null 2>&1; then
                (cd dist && zip -qr "$name.zip" "$name")
            else
                powershell -NoProfile -Command "Compress-Archive -Path 'dist/$name' -DestinationPath 'dist/$name.zip'"
            fi
            ;;
        *) tar -C dist -czf "dist/$name.tar.gz" "$name" ;;
    esac
    rm -rf "dist/$name"
done

cd dist
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum nattowok-*.tar.gz nattowok-*.zip 2>/dev/null > SHA256SUMS || true
else
    shasum -a 256 nattowok-*.tar.gz nattowok-*.zip 2>/dev/null > SHA256SUMS || true
fi
echo "==> Packages in dist/:"
cat SHA256SUMS
