#!/usr/bin/env python3
"""Check APK installation and revision rollback in disposable offline roots."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk-tool', required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--upgrade', type=Path, required=True,
                        help='test-only newer revision of the same MIPS binary')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='xrust-apk-mips-') as temporary:
        base = Path(temporary)

        def apk(root, *command, success=True, architecture='mipsel_24kc'):
            prefix = ['unshare', '-r'] if os.geteuid() else []
            options = ['--no-scripts'] if command[0] in ('add', 'del') else []
            result = subprocess.run([*prefix, args.apk_tool, '--root', str(root), '--arch', architecture,
                                     '--no-network', '--allow-untrusted', *options,
                                     '--force-non-repository',
                                     *map(str, command)], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(result.stdout, end='')
            if (result.returncode == 0) != success:
                raise AssertionError(f'Unexpected APK result: {command}')
            return result.stdout

        # Empty dependency fixtures are local metadata, never firmware files.
        dependencies = []
        for name in ['ca-bundle', 'kmod-tun', 'libc', 'libgcc']:
            package = base / f'{name}.apk'
            subprocess.run([args.apk_tool, 'mkpkg', '--output', str(package),
                            '-I', f'name:{name}', '-I', 'version:1-r1',
                            '-I', 'arch:noarch', '-I', 'description:offline test fixture',
                            '-I', 'license:CC0-1.0'], check=True)
            dependencies.append(package)
        wrong = base / 'wrong-architecture'
        apk(wrong, 'add', '--initdb', *dependencies, architecture='mips_24kc')
        output = apk(wrong, 'add', args.package.resolve(), success=False, architecture='mips_24kc')
        assert 'mipsel_24kc' in output or 'architecture' in output or 'no such package' in output
        assert not (wrong / 'usr/lib/rust-x/sing-box').exists()
        root = base / 'root'
        apk(root, 'add', '--initdb', *dependencies[:-1])
        output = apk(root, 'add', args.package.resolve(), success=False)
        assert 'libgcc' in output
        assert not (root / 'usr/lib/rust-x/sing-box').exists()
        apk(root, 'add', dependencies[-1], args.package.resolve())
        binary = root / 'usr/lib/rust-x/sing-box'
        original = hashlib.sha256(binary.read_bytes()).hexdigest()
        metadata = json.loads((root / 'usr/share/rust-x/build.json').read_text())
        assert metadata['architecture'] == 'mipsel_24kc' and metadata['binary_sha256'] == original
        uci = root / 'etc/config/sing-box'
        uci.write_text(uci.read_text() + '\n# operator settings preserved\n')
        settings = uci.read_bytes()
        apk(root, 'add', args.upgrade.resolve())
        assert uci.read_bytes() == settings
        assert f'{metadata["version"]}-r2' in apk(root, 'list', '--installed', 'rust-x')
        apk(root, 'add', args.package.resolve())
        assert uci.read_bytes() == settings
        assert f'{metadata["version"]}-r1' in apk(root, 'list', '--installed', 'rust-x')
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == original
        apk(root, 'del', 'rust-x')
        assert not binary.exists() and uci.read_bytes() == settings
        print('MIPS APK: architecture/dependency rejection, install, revision '
              'upgrade/rollback and preserved configuration: OK')


if __name__ == '__main__':
    main()
