#!/usr/bin/env python3
"""Exercise real opkg in temporary offline roots, never on the host system."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--opkg', required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--upgrade', type=Path, required=True,
                        help='test-only newer revision of the same MIPS binary')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='xrust-opkg-mips-') as temporary:
        base = Path(temporary)
        root = base / 'root'
        status = root / 'usr/lib/opkg/status'
        status.parent.mkdir(parents=True)
        (root / 'tmp').mkdir()
        config = base / 'opkg.conf'

        def setup(architecture, dependencies):
            config.write_text(f'dest root /\narch all 1\narch {architecture} 10\n')
            status.write_text(''.join(
                f'Package: {name}\nVersion: 1\nArchitecture: {architecture}\n'
                'Status: install ok installed\n\n' for name in dependencies))
            info = status.parent / 'info'
            info.mkdir(exist_ok=True)
            for name in dependencies:
                (info / f'{name}.list').write_text('')

        def opkg(*command, success=True):
            result = subprocess.run([args.opkg, '-f', str(config), '-o', str(root),
                                     *map(str, command)], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(result.stdout, end='')
            if (result.returncode == 0) != success:
                raise AssertionError(f'Unexpected opkg result: {command}')
            return result.stdout

        # Only dependency *status fixtures* are installed. No firmware packages
        # or repositories are downloaded, and offline hooks are not forced.
        dependencies = ['ca-bundle', 'kmod-tun', 'libc', 'libgcc']
        setup('mips_24kc', dependencies)
        output = opkg('install', args.package.resolve(), success=False)
        assert 'architecture' in output
        assert not (root / 'usr/lib/rust-x/sing-box').exists()
        setup('mipsel_24kc', dependencies[:-1])
        output = opkg('install', args.package.resolve(), success=False)
        assert 'libgcc' in output
        assert not (root / 'usr/lib/rust-x/sing-box').exists()
        setup('mipsel_24kc', dependencies)
        opkg('install', args.package.resolve())
        binary = root / 'usr/lib/rust-x/sing-box'
        original = hashlib.sha256(binary.read_bytes()).hexdigest()
        metadata = json.loads((root / 'usr/share/rust-x/build.json').read_text())
        assert metadata['architecture'] == 'mipsel_24kc'
        assert metadata['binary_sha256'] == original
        uci = root / 'etc/config/sing-box'
        uci.write_text(uci.read_text() + "\n# operator settings preserved\n")
        settings = uci.read_bytes()
        opkg('--force-reinstall', 'install', args.package.resolve())
        assert uci.read_bytes() == settings
        opkg('install', args.upgrade.resolve())
        assert uci.read_bytes() == settings
        assert f'Version: {metadata["version"]}-2' in opkg('status', 'rust-x')
        opkg('--force-downgrade', 'install', args.package.resolve())
        assert uci.read_bytes() == settings
        assert f'Version: {metadata["version"]}-1' in opkg('status', 'rust-x')
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == original
        opkg('remove', 'rust-x')
        assert not binary.exists()
        assert uci.read_bytes() == settings
        print('MIPS IPK: architecture/dependency rejection, install, reinstall, '
              'revision upgrade/rollback and preserved configuration: OK')


if __name__ == '__main__':
    main()
