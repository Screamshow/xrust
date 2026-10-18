#!/usr/bin/env python3
"""Finalize a draft using the existing mirror signer; no signing key is copied."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

REPO = 'Screamshow/xrust'
HOST = 'root@192.168.200.138'
APK = '/root/.cache/forkop/openwrt-sdk/extracted/apk/staging_dir/host/bin/apk'
KEY = '/srv/mirror/keys/forkop-apk.pem'
PUBLIC_KEY = '/srv/mirror/public/forkop/forkop-apk.pem'


def run(*args, capture=False):
    return subprocess.check_output(args, text=True) if capture else subprocess.check_call(args)


def validate(directory, version, signed=False):
    manifest = json.loads((directory / 'openwrt-manifest.json').read_text())
    if manifest['version'] != version:
        raise ValueError('Unexpected manifest version')
    assets = manifest['assets']
    expected = {(arch, fmt) for arch in ('x86_64', 'aarch64_cortex-a53') for fmt in ('apk', 'ipk')}
    if len(assets) != 4 or {(a['architecture'], a['format']) for a in assets} != expected:
        raise ValueError('Expected APK/IPK for both supported architectures')
    for asset in assets:
        revision = 'r1' if asset['format'] == 'apk' else '1'
        name = f'rust-x_{version}-{revision}_{asset["architecture"]}.{asset["format"]}'
        if asset['package'] != 'rust-x' or asset['file'] != name or asset['version'] != f'{version}-{revision}':
            raise ValueError('Unexpected package identity')
        package = directory / name
        if package.stat().st_size != asset['size'] or hashlib.sha256(package.read_bytes()).hexdigest() != asset['sha256']:
            raise ValueError(f'Package checksum mismatch: {name}')
        if signed and asset['format'] == 'apk' and not asset.get('signed'):
            raise ValueError('Unsigned APK in final manifest')
    if signed:
        if not manifest.get('apk_signed'):
            raise ValueError('Manifest is not signed-package metadata')
        digest = hashlib.sha256((directory / 'forkop-apk.pem').read_bytes()).hexdigest()
        if digest != manifest['signing_public_key_sha256']:
            raise ValueError('Public key hash mismatch')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--ssh-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--publish', action='store_true', help='Publish the verified draft after signing')
    args = parser.parse_args()
    if not re.fullmatch(r'rust-x-v\d+\.\d+\.\d+', args.tag):
        raise ValueError('Invalid release tag')
    version = args.tag.removeprefix('rust-x-v')
    release = json.loads(run('gh', 'release', 'view', args.tag, '--repo', REPO, '--json', 'isDraft,databaseId', capture=True))
    if not release['isDraft']:
        raise ValueError('Refusing to replace an already public release')
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rust-x-finalize-') as temporary:
        directory = Path(temporary)
        for pattern in ('*.apk', '*.ipk', 'openwrt-manifest.json'):
            run('gh', 'release', 'download', args.tag, '--repo', REPO, '--pattern', pattern, '--dir', str(directory))
        manifest = validate(directory, version)
        source = manifest['binary_source_commit']
        if not re.fullmatch(r'[0-9a-f]{40}', source):
            raise ValueError('Invalid source commit')
        tagged = run('gh', 'api', f'repos/{REPO}/commits/{args.tag}', '--jq', '.sha', capture=True).strip()
        if tagged != source:
            raise ValueError('Release tag does not match binary source commit')
        remote = f'/srv/mirror/build/rust-x-finalize/{args.tag}-{source[:12]}'
        ssh = ['ssh', '-i', str(args.ssh_key), '-o', 'BatchMode=yes', HOST]
        scp = ['scp', '-i', str(args.ssh_key), '-o', 'BatchMode=yes']
        run(*ssh, f'umask 077; mkdir -p {shlex.quote(remote)}')
        signer = Path(__file__).with_name('sign_openwrt.py')
        run(*scp, str(signer), *[str(directory / a['file']) for a in manifest['assets']],
            str(directory / 'openwrt-manifest.json'), f'{HOST}:{remote}/')
        command = f'python3 {remote}/sign_openwrt.py {remote} --apk-tool {APK} --sign-key {KEY} --public-key {PUBLIC_KEY}'
        run(*ssh, command)
        # Verification is performed on the signer against the existing trusted
        # public key before any release asset is replaced.
        run(*ssh, f'cd {remote} && {APK} --keys-dir {remote} verify rust-x_{version}-r1_aarch64_cortex-a53.apk rust-x_{version}-r1_x86_64.apk && sha256sum -c OPENWRT-SHA256SUMS')
        names = [a['file'] for a in manifest['assets']] + ['openwrt-manifest.json', 'forkop-apk.pem', 'OPENWRT-SHA256SUMS']
        for name in names:
            run(*scp, f'{HOST}:{remote}/{name}', str(args.output / name))
        final = validate(args.output, version, signed=True)
        if final['binary_source_commit'] != source:
            raise ValueError('Source changed during signing')
        checksum = args.output / 'SHA256SUMS'
        checksum.write_text(''.join(f'{a["sha256"]}  {a["file"]}\n' for a in final['assets']))
        run('gh', 'release', 'upload', args.tag, '--repo', REPO, '--clobber',
            *[str(args.output / n) for n in names if n != 'OPENWRT-SHA256SUMS'], str(checksum))
        # The tag endpoint excludes drafts; address the authenticated draft by ID.
        published_assets = json.loads(run('gh', 'api', f'repos/{REPO}/releases/{release["databaseId"]}', capture=True))['assets']
        uploaded = {asset['name']: asset for asset in published_assets}
        for name in [n for n in names if n != 'OPENWRT-SHA256SUMS'] + ['SHA256SUMS']:
            local = args.output / name
            remote_asset = uploaded[name]
            if remote_asset['size'] != local.stat().st_size or remote_asset.get('digest') != 'sha256:' + hashlib.sha256(local.read_bytes()).hexdigest():
                raise ValueError(f'Uploaded asset verification failed: {name}')
        if args.publish:
            run('gh', 'release', 'edit', args.tag, '--repo', REPO, '--draft=false')
        print('Signed packages verified; ' + ('release published' if args.publish else 'release remains a draft'))


if __name__ == '__main__':
    main()
