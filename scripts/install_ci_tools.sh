#!/usr/bin/env bash
# Run as root on Ubuntu CI runners. Keep APT signatures and package hashes.
set -euo pipefail
apt_options=(-o Acquire::Retries=1 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15)
if apt-get "${apt_options[@]}" -o APT::Update::Error-Mode=any update &&
   apt-get "${apt_options[@]}" install -y "$@"; then
    exit 0
fi

echo 'Default Ubuntu archive unavailable; retrying through the kernel.org mirror.' >&2
# Hosted Ubuntu images use either deb822 sources or mirror-list files.
# Change only Ubuntu archive URLs, retaining suites, components and Signed-By.
for source in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources \
    /etc/apt/apt-mirrors.txt /etc/apt/apt-mirrors-security.txt; do
    if [ -f "$source" ]; then
        sed -i -E 's@https?://(azure\.archive|archive|security)\.ubuntu\.com/ubuntu/?@https://mirrors.edge.kernel.org/ubuntu/@g' "$source"
    fi
done
apt-get "${apt_options[@]}" -o APT::Update::Error-Mode=any update
apt-get "${apt_options[@]}" install -y "$@"
