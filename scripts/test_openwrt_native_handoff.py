#!/usr/bin/env python3
"""Verify the Xrust executable handoff in disposable offline x86_64 package roots."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def run(command):
    return subprocess.check_output([str(arg) for arg in command], text=True)


def package(directory, fmt):
    [path] = list(directory.resolve().glob(f'rust-x_*_x86_64.{fmt}'))
    return path


def verify_native(root):
    binary = root / 'usr/bin/xrust'
    previous_binary = root / 'usr/lib/rust-x/sing-box'
    previous_init = root / 'etc/init.d/sing-box'
    metadata = json.loads((root / 'usr/share/rust-x/build.json').read_text())
    version = metadata['version']
    assert metadata['minimum_forkop_major'] == 3 and metadata['architecture'] == 'x86_64'
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == metadata['binary_sha256']
    assert not previous_binary.exists() and not previous_init.exists()

    banner = run([binary, 'version']).splitlines()
    assert banner[0] == f'xrust version {version}'
    assert any(line.startswith('Features: ') for line in banner)
    assert any(line.startswith('Tags: ') for line in banner)

    # Run the installed shim against the binary inside the disposable root.
    shim = (root / 'usr/bin/sing-box').read_text().replace('/usr/bin/xrust', shlex.quote(str(binary)))
    assert run(['sh', '-c', shim, 'sing-box', 'version']) == f'sing-box version 1.14.2-rust-x.{version}\n'
    assert subprocess.run(['sh', '-c', shim, 'sing-box', 'run'], check=False).returncode != 0
    assert subprocess.run(['sh', '-c', shim, 'sing-box', 'check'], check=False).returncode != 0


def verify_transition(root, install, legacy, native):
    previous_binary = root / 'usr/lib/rust-x/sing-box'
    previous_config = root / 'etc/config/sing-box'
    install(native)
    verify_native(root)
    assert not previous_config.exists()

    install(legacy, downgrade=True)
    assert previous_binary.is_file()
    previous_config.write_text(previous_config.read_text() + '\n# operator setting\n')
    saved_config = previous_config.read_bytes()

    install(native)
    verify_native(root)

    install(legacy, downgrade=True)
    assert previous_binary.is_file()
    assert not (root / 'usr/bin/xrust').exists()
    assert previous_config.read_bytes() == saved_config
    install(native)
    verify_native(root)


def verify_apk(args, root):
    prefix = ['unshare', '-r'] if os.geteuid() else []
    dependencies = []
    for name in ('ca-bundle', 'kmod-tun'):
        fixture = root.parent / f'{name}.apk'
        run([args.apk_tool, 'mkpkg', '--output', fixture, '-I', f'name:{name}',
             '-I', 'version:1-r1', '-I', 'arch:noarch', '-I', 'license:CC0-1.0'])
        dependencies.append(fixture)
    apk = [*prefix, args.apk_tool, '--root', root, '--arch', 'x86_64', '--no-network',
           '--allow-untrusted', '--no-scripts', '--force-non-repository']
    run([*apk, 'add', '--initdb', *dependencies])

    def install(path, downgrade=False):
        run([*apk, 'add', path])

    verify_transition(root, install, package(args.legacy, 'apk'), package(args.native, 'apk'))


def verify_ipk(args, root):
    status = root / 'usr/lib/opkg/status'
    status.parent.mkdir(parents=True)
    (root / 'tmp').mkdir()
    info = status.parent / 'info'
    info.mkdir()
    dependencies = ('ca-bundle', 'kmod-tun')
    status.write_text(''.join(f'Package: {name}\nVersion: 1\nArchitecture: x86_64\n'
                              'Status: install ok installed\n\n' for name in dependencies))
    for name in dependencies:
        (info / f'{name}.list').touch()
    config = root.parent / 'opkg.conf'
    config.write_text('dest root /\narch all 1\narch x86_64 10\n')

    def install(path, downgrade=False):
        options = ['--force-downgrade'] if downgrade else []
        run([args.opkg, '-f', config, '-o', root, *options, 'install', path])

    verify_transition(root, install, package(args.legacy, 'ipk'), package(args.native, 'ipk'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk-tool', required=True)
    parser.add_argument('--opkg', required=True)
    parser.add_argument('--legacy', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='xrust-native-handoff-') as temporary:
        root = Path(temporary)
        verify_apk(args, root / 'apk')
        verify_ipk(args, root / 'ipk')
    print('APK and IPK: fresh native install, legacy upgrade/rollback and version-only handoff passed')


if __name__ == '__main__':
    main()
