#!/usr/bin/env bash
# Uncompressed release executable budget in bytes.
case "${1:?Rust target triple required}" in
    x86_64-unknown-linux-musl) echo 13631488 ;;
    *) echo 12582912 ;;
esac
