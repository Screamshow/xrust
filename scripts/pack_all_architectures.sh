#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
output="${1:-}"
output="${output:-dist/rust-x-v$version}"
mkdir -p "$output"
archives=()
for cpu in x86_64 aarch64; do
    binary="target/$cpu-unknown-linux-musl/release/xrust"
    name="rust-x-$cpu-v$version"
    test -f "$binary"
    test "$(wc -c < "$binary")" -le 12582912
    cp "$binary" "$output/$name"
    chmod +x "$output/$name"
    tar -czf "$output/$name.tar.gz" -C "$output" "$name"
    rm -f "$output/$name"
    archives+=("$name.tar.gz")
done
(cd "$output"; sha256sum "${archives[@]}" > SHA256SUMS; sha256sum -c SHA256SUMS)
