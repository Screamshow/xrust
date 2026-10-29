#!/usr/bin/env bash
# Download only the native OpenWrt cross toolchain, never router packages.
set -euo pipefail
name=openwrt-toolchain-24.10.4-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64
digest=2ede1fb29175bf7b8888606017dd71123e8e85679956ef708e626d1b60fa3065
cache="${MIPS_CACHE_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/forkop-mips-toolchain}"
mkdir -p "$cache"
archive="$cache/$name.tar.zst"
if [ ! -f "$archive" ]; then
    curl -fLSs --retry 3 "https://downloads.openwrt.org/releases/24.10.4/targets/ramips/mt76x8/$name.tar.zst" -o "$archive.part"
    echo "$digest  $archive.part" | sha256sum -c - >&2
    mv "$archive.part" "$archive"
fi
echo "$digest  $archive" | sha256sum -c - >&2
compiler="$cache/$name/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin/mipsel-openwrt-linux-musl-gcc"
if [ ! -x "$compiler" ]; then tar --zstd -xf "$archive" -C "$cache"; fi
test -x "$compiler"
dirname "$(dirname "$compiler")"
