# Releasing Xrust

The product/package name remains Xrust / rust-x. APKs use the same mirror-host
key and apk-tools as Sing-Box X. The private signing key stays on that host.
No new runner or signing key in GitHub Secrets is required.

1. Commit the release source on main with matching workspace/lockfile version
   and docs/releases/VERSION.md. Push a matching `rust-x-vVERSION` tag.
2. The workflow builds static x86_64 and ARM64 binaries, enforces the size budget,
   packages APK/IPK, and creates a draft with the source manifest. Unsigned build
   packages are never intentionally published as a public release.
3. On the operator computer with authenticated `gh` and mirror SSH access, run:

   ```powershell
   python scripts/finalize_release.py --tag rust-x-v0.0.2 --ssh-key PATH_TO_MIRROR_SSH_IDENTITY --output PATH_TO_FINAL_PACKAGES --publish
   ```

The finalizer validates package identities, revisions, architectures, lengths,
hashes and tagged source commit. It signs on the mirror, verifies APK signatures
using the existing public key, and checks the final manifest. It replaces the
draft assets with signed APKs, unchanged IPKs, updated SHA256SUMS, public key and
manifest; GitHub asset digests are verified before publication. Without
`--publish`, the verified assets remain in a draft for review. Already public
releases are never replaced by this command.

Generic x86_64 builds do not require AVX2. Existing runtime crypto feature
detection remains available. The OpenWrt package payload continues to use the
sing-box wrapper and existing configuration/service paths.
