#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${MIPS_TOOLCHAIN:?Set MIPS_TOOLCHAIN to the OpenWrt mipsel_24kc toolchain directory}"
compiler="$MIPS_TOOLCHAIN/bin/mipsel-openwrt-linux-musl-gcc"
test -x "$compiler"
export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER="$compiler"
export CC_mipsel_unknown_linux_musl="$compiler"
export AR_mipsel_unknown_linux_musl="$MIPS_TOOLCHAIN/bin/mipsel-openwrt-linux-musl-ar"
if [ -z "${STAGING_DIR:-}" ]; then
    export STAGING_DIR="$(dirname "$MIPS_TOOLCHAIN")"
fi
# Stable Rust ships the target specification but no prebuilt std for MIPS.
# Enable only cargo's build-std with the exact rust-src belonging to rustc.
export RUSTC_BOOTSTRAP=1
cargo build --locked -Z build-std=std,panic_abort --workspace \
    --no-default-features --features rust-x --release --target mipsel-unknown-linux-musl "$@"
