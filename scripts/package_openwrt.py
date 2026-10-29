#!/usr/bin/env python3
"""Package released Xrust ELF binaries for OpenWrt 24/25."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = ['ca-bundle', 'kmod-tun']
CONFLICTS = ['sing-box', 'sing-box-x', 'sing-box-tiny', 'sing-box-extended']
TARGETS = [
    ('aarch64', 'aarch64_generic', 2, 183),
    ('aarch64', 'aarch64_cortex-a73', 2, 183),
    ('aarch64', 'aarch64_cortex-a53', 2, 183),
    ('x86_64', 'x86_64', 2, 62),
    ('mipsel', 'mipsel_24kc', 1, 8),
]


def validate_elf(binary, cpu, elf_class, machine):
    if (len(binary) < 52 or binary[:6] != b'\x7fELF' + bytes([elf_class, 1]) or
            int.from_bytes(binary[18:20], 'little') != machine):
        raise ValueError(f'Wrong ELF architecture: {cpu}')
    if cpu != 'mipsel':
        return
    # 24Kc has no FPU: reject a valid MIPS ELF if its ABI needs one.
    flags = struct.unpack_from('<I', binary, 36)[0]
    if flags & 0xf0000000 != 0x70000000 or flags & 0xf000 != 0x1000:
        raise ValueError('MIPS package requires MIPS32r2 O32')
    offset = struct.unpack_from('<I', binary, 32)[0]
    entry_size, count, names_index = struct.unpack_from('<HHH', binary, 46)
    if entry_size != 40 or names_index >= count or offset + count * entry_size > len(binary):
        raise ValueError('Invalid MIPS section table')
    sections = [struct.unpack_from('<10I', binary, offset + i * entry_size) for i in range(count)]
    names_section = sections[names_index]
    names = binary[names_section[4]:names_section[4] + names_section[5]]
    for section in sections:
        name = names[section[0]:].split(b'\0', 1)[0]
        if name == b'.MIPS.abiflags':
            data = binary[section[4]:section[4] + section[5]]
            if len(data) < 24 or data[2:4] != bytes([32, 2]) or data[7] != 3:
                raise ValueError('MIPS package requires soft-float ABI')
            return
    raise ValueError('MIPS ELF lacks ABI flags')
NATIVE_STOP = b'''#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
[ ! -x /etc/init.d/forkop-tailscale ] || /etc/init.d/forkop-tailscale stop
if [ -x /etc/init.d/forkop ] && /etc/init.d/forkop status >/dev/null 2>&1; then
    mkdir -p /var/run/forkop
    touch /var/run/forkop/rust-x-package-restart
    /etc/init.d/forkop stop || exit 1
fi
exit 0
'''
NATIVE_START = b'''#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
if [ -f /var/run/forkop/rust-x-package-restart ] && [ -x /etc/init.d/forkop ]; then
    /etc/init.d/forkop start && rm -f /var/run/forkop/rust-x-package-restart
fi
if [ -f /etc/forkop-tailscale/enabled ] && [ -x /etc/init.d/forkop-tailscale ] &&
   [ "$(cat /etc/forkop/sing-box-variant 2>/dev/null)" = rust-x ]; then
    /etc/init.d/forkop-tailscale start || true
fi
exit 0
'''

def tar_bytes(files):
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode='wb', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w', format=tarfile.GNU_FORMAT) as tar:
            directories = {str(p) for n, _, _ in files for p in PurePosixPath(n).parents if str(p) != '.'}
            for name in sorted(directories, key=lambda n: (n.count('/'), n)):
                item = tarfile.TarInfo(name + '/'); item.type = tarfile.DIRTYPE; item.mode = 0o755
                tar.addfile(item)
            for name, data, mode in sorted(files):
                item = tarfile.TarInfo(name); item.size = len(data); item.mode = mode
                tar.addfile(item, io.BytesIO(data))
    return stream.getvalue()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--binaries', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--apk-tool', required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--revision', type=int, default=1)
    p.add_argument('--source-commit', required=True)
    p.add_argument('--cpus', default='aarch64,x86_64,mipsel',
                   help='comma-separated subset of aarch64,x86_64,mipsel (default: all)')
    a = p.parse_args(); a.output.mkdir(parents=True, exist_ok=True)
    assets = []
    requested = a.cpus.split(',')
    if not requested or len(requested) != len(set(requested)) or set(requested) - {'aarch64', 'x86_64', 'mipsel'}:
        p.error('Invalid --cpus selection')
    for cpu, arch, elf_class, machine in TARGETS:
        if cpu not in requested: continue
        binary = (a.binaries / f'rust-x-{cpu}-v{a.version}').read_bytes()
        validate_elf(binary, cpu, elf_class, machine)
        dependencies = DEPENDENCIES + (['libc', 'libgcc'] if cpu == 'mipsel' else [])
        metadata = dict(package='rust-x', version=a.version, package_revision=a.revision,
                        architecture=arch, source_commit=a.source_commit,
                        binary_bytes=len(binary), binary_sha256=hashlib.sha256(binary).hexdigest(),
                        configuration_baseline='1.14.2', packed=False)
        # The binary, installed under the sing-box name, prints the version
        # block Forkop X reads itself.
        wrapper = b'''#!/bin/sh
exec /usr/lib/rust-x/sing-box "$@"
'''
        files = [('usr/lib/rust-x/sing-box', binary, 0o755), ('usr/bin/sing-box', wrapper, 0o755),
                 ('usr/share/rust-x/build.json', (json.dumps(metadata, indent=2)+'\n').encode(), 0o644)]
        for path in ['etc/init.d/sing-box', 'etc/config/sing-box']:
            files.append((path, (ROOT/'packaging/files'/path).read_bytes(), 0o755 if 'init.d' in path else 0o644))
        size = sum(len(data) for _, data, _ in files)
        control = f'''Package: rust-x
Version: {a.version}-{a.revision}
Architecture: {arch}
Installed-Size: {size}
Depends: {', '.join(dependencies)}
Conflicts: {', '.join(CONFLICTS)}
Provides: sing-box
Section: net
License: GPL-3.0-only
Maintainer: Screamshow
Source: https://github.com/Screamshow/xrust
Description: Xrust router core for Forkop
'''
        ipk = a.output/f'rust-x_{a.version}-{a.revision}_{arch}.ipk'
        ipk.write_bytes(tar_bytes([('debian-binary', b'2.0\n', 0o644),
            ('control.tar.gz', tar_bytes([('control', control.encode(), 0o644), ('conffiles', b'/etc/config/sing-box\n', 0o644), ('prerm', NATIVE_STOP, 0o755), ('postinst', NATIVE_START, 0o755)]), 0o644),
            ('data.tar.gz', tar_bytes(files), 0o644)]))
        apk = a.output/f'rust-x_{a.version}-r{a.revision}_{arch}.apk'
        with tempfile.TemporaryDirectory(prefix='rust-x-package-') as temp:
            payload = Path(temp)/'payload'; payload.mkdir()
            for name, data, mode in files:
                f = payload/name; f.parent.mkdir(parents=True, exist_ok=True); f.write_bytes(data); f.chmod(mode)
            meta = payload/'lib/apk/packages'; meta.mkdir(parents=True)
            (meta/'rust-x.list').write_text(''.join('/'+n+'\n' for n, _, _ in files))
            for suffix in ['conffiles', 'conffiles_static']:
                (meta/f'rust-x.{suffix}').write_text('/etc/config/sing-box\n')
            for f in [payload, *payload.rglob('*')]:
                if f.is_dir(): f.chmod(0o755)
                elif f.parent == meta: f.chmod(0o644)
                os.utime(f, (0, 0))
            cmd = [a.apk_tool, 'mkpkg', '--files', str(payload), '--output', str(apk.resolve())]
            for hook, content in [('pre-upgrade', NATIVE_STOP), ('pre-deinstall', NATIVE_STOP), ('post-upgrade', NATIVE_START), ('post-install', NATIVE_START)]:
                script = Path(temp)/hook
                script.write_bytes(content)
                script.chmod(0o755)
                cmd += ['-s', f'{hook}:{script}']
            fields = dict(name='rust-x', version=f'{a.version}-r{a.revision}', arch=arch,
                          description='Xrust router core for Forkop', license='GPL-3.0-only',
                          origin='rust-x', maintainer='Screamshow', url='https://github.com/Screamshow/xrust',
                          depends=' '.join(dependencies + ['!'+c for c in CONFLICTS]), provides='sing-box')
            for key, value in fields.items(): cmd += ['-I', f'{key}:{value}']
            if os.geteuid() == 0:
                for f in [payload, *payload.rglob('*')]: os.chown(f, 0, 0)
                subprocess.run(cmd, check=True)
            else:
                subprocess.run(['unshare', '-r', 'sh', '-c', 'chown -R 0:0 "$1"; shift; exec "$@"', 'sh', str(payload), *cmd], check=True)
        for package in [ipk, apk]:
            installed_size = size
            if package.suffix == '.apk':
                dump = subprocess.check_output([a.apk_tool, 'adbdump', str(package)], text=True)
                installed_size = int(re.search(r'^  installed-size: (\d+)$', dump, re.M).group(1))
            assets.append(dict(package='rust-x', version=f'{a.version}-'+('r' if package.suffix=='.apk' else '')+str(a.revision),
                architecture=arch, format=package.suffix[1:], file=package.name,
                size=package.stat().st_size, installed_size=installed_size, binary_bytes=len(binary),
                sha256=hashlib.sha256(package.read_bytes()).hexdigest(), dependencies=dependencies))
    (a.output/'openwrt-manifest.json').write_text(json.dumps(dict(version=a.version, binary_source_commit=a.source_commit,
        packaging_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), apk_signed=False, assets=assets), indent=2)+'\n')
    (a.output/'OPENWRT-SHA256SUMS').write_text(''.join(f'{x["sha256"]}  {x["file"]}\n' for x in assets))

if __name__ == '__main__': main()
