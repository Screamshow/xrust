#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
rustup component add rust-src
export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-musl-gcc}"
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    cargo build --locked -p core-cli --no-default-features --features rust-x --release --target "$target"
done
export MIPS_TOOLCHAIN="${MIPS_TOOLCHAIN:-$(bash scripts/openwrt_mips_toolchain.sh)}"
bash scripts/build_mips_openwrt.sh
bash scripts/pack_all_architectures.sh "${1:-}"
