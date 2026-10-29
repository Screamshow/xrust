# Xrust OpenWrt packages

For the 0.0.29 dev candidate, supported package architectures are
`aarch64_generic`, `aarch64_cortex-a53`, `aarch64_cortex-a73`, `x86_64` and
`mipsel_24kc`, each in APK and IPK. MIPS additionally requires the firmware's
`libc` and `libgcc`; no foreign firmware dependencies are bundled. MIPS uses
MIPS32r2 O32 little-endian soft-float. See
[preparation and hardware limitations](mipsel-openwrt-preparation-2026-10-29.md).
The following section records the initial 0.0.1 packaging baseline.

Xrust 0.0.1 has APK `0.0.1-r1` for OpenWrt 25 and IPK `0.0.1-1`
for OpenWrt 24. Architectures: `aarch64_cortex-a53` (ARM64) and `x86_64`.
The payload uses the existing release binaries without UPX compression.

The package is `rust-x`, provides `sing-box` and conflicts with other
sing-box package variants. Dependencies: `ca-bundle`, `kmod-tun`.
The native executable lives at `/usr/lib/rust-x/sing-box`; the wrapper
at `/usr/bin/sing-box` supplies the existing Forkop configuration capability
baseline while reporting Xrust identity separately. This baseline does not
claim every Sing-Box feature or protocol. Existing configuration is retained;
the included procd service is disabled by default on fresh installations.

APK assets are signed with the existing Forkop mirror key. The public key is at https://mirror.51343.ru/forkop/forkop-apk.pem;
routers must trust this public key in `/etc/apk/keys/`
(existing mirror installations already use it). Installation does not require
`--allow-untrusted`. These release assets are not a package feed. Existing Forkop
defaults, component selectors and mirror update policy are unchanged.

`scripts/package_openwrt.py` validates ELF machine identity and produces
both formats, hashes and `openwrt-manifest.json`. The separate packaging
workflow retains packaging outputs as internal build artifacts; future core
releases package both formats automatically. The original 0.0.1 core tag
remains unchanged; the packaging source is available on main.

Unsigned build outputs are signed on the mirror using `scripts/sign_openwrt.py`
with the mirror's existing APK tool, private key path and published public key.
The script checks input hashes, signs APKs individually, verifies signatures,
and updates manifest hashes, retaining the unsigned hashes for provenance.
The private key stays on the mirror; it is never bundled or sent to GitHub.
The packaging workflow refuses to overwrite already signed release packages.

On 2026-10-10, real x86_64 APK/IPK installations on the existing OpenWrt 25/24
VMs preserved `/etc/config/sing-box`, passed native configuration checks,
started the normal sing-box service through Forkop and reached watchdog ready.
The APK installation passed all 42 subscription group-entry HTTPS requests.
ARM64 package architecture and metadata were checked; ARM64 execution was
not tested because both available VMs are x86_64.
Both APK signatures were verified with the public key; the x86_64 signed APK
was reinstalled on OpenWrt 25 without `--allow-untrusted`.
