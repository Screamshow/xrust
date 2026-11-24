import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('finalizer', Path(__file__).with_name('finalize_release.py'))
finalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finalizer)

class OpenWrtArchitectures(unittest.TestCase):
    def test_restart_failure_remains_visible_and_retryable(self):
        if os.name != "posix":
            self.skipTest("OpenWrt postinst needs a POSIX shell")
        import package_openwrt as packager
        for hook in [packager.LEGACY_START, packager.NATIVE_START]:
            with tempfile.TemporaryDirectory() as work:
                root = Path(work)
                marker = root / "restart"
                marker.touch()
                service = root / "forkop"
                service.write_text("#!/bin/sh\nexit 7\n")
                service.chmod(0o755)
                script = hook.decode().replace("/etc/init.d/forkop", str(service)).replace(
                    "/var/run/forkop/rust-x-package-restart", str(marker)).replace(
                    "/usr/lib/forkop/xrust/binary.uc", str(service))
                self.assertEqual(subprocess.run(["sh", "-c", script]).returncode, 7)
                self.assertTrue(marker.exists())
                service.write_text("#!/bin/sh\nexit 0\n")
                self.assertEqual(subprocess.run(["sh", "-c", script]).returncode, 0)
                self.assertFalse(marker.exists())

    def test_release_size_budgets(self):
        if not shutil.which("bash"):
            self.skipTest("requires bash")
        script = Path(__file__).with_name("openwrt_size_budget.sh")
        for cpu, mib in [("x86_64", 13), ("aarch64", 12), ("mipsel", 12)]:
            actual = subprocess.check_output(["bash", str(script), f"{cpu}-unknown-linux-musl"])
            self.assertEqual(int(actual), mib << 20)

    @unittest.skipUnless(os.name == "posix", "Unix packaging script")
    def test_docker_archives_use_the_workspace_version(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / "scripts").mkdir()
            (root / "openwrt").mkdir()
            (root / "Cargo.toml").write_text('[workspace.package]\nversion = "9.8.7"\n')
            script = Path(__file__).with_name("pack_release_docker.sh")
            shutil.copy(script, root / "scripts" / script.name)
            for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "x86_64-unknown-linux-gnu"]:
                out = root / "target" / target / "release"
                out.mkdir(parents=True)
                (out / "xrust").write_bytes(b"fixture")
            subprocess.run(["bash", str(root / "scripts" / script.name)], check=True, stdout=subprocess.DEVNULL)
            archives = list((root / "dist").glob("*.tar.gz"))
            self.assertEqual(len(archives), 4)
            self.assertTrue(all(path.name.endswith("-v9.8.7.tar.gz") for path in archives))

    def check_assets(self, pairs):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            assets = []
            for arch, fmt in pairs:
                revision = 'r1' if fmt == 'apk' else '1'
                name = f'rust-x_0.0.27-{revision}_{arch}.{fmt}'
                data = name.encode()
                (directory / name).write_bytes(data)
                assets.append(dict(package='rust-x', version=f'0.0.27-{revision}', architecture=arch,
                                   format=fmt, file=name, size=len(data), sha256=hashlib.sha256(data).hexdigest()))
            (directory / 'openwrt-manifest.json').write_text(json.dumps(dict(version='0.0.27', assets=assets)))
            return finalizer.validate(directory, '0.0.27')

    def test_historical_and_beam_architectures(self):
        original = [(arch, fmt) for arch in ('aarch64_cortex-a53', 'x86_64') for fmt in ('apk', 'ipk')]
        self.assertEqual(len(self.check_assets(original)['assets']), 4)
        beam = [('aarch64_cortex-a73', fmt) for fmt in ('apk', 'ipk')]
        self.assertEqual(len(self.check_assets(original + beam)['assets']), 6)
        generic = [('aarch64_generic', fmt) for fmt in ('apk', 'ipk')]
        self.assertEqual(len(self.check_assets(original + beam + generic)['assets']), 8)
        self.assertEqual(len(self.check_assets(original + generic)['assets']), 6)
        mips = [('mipsel_24kc', fmt) for fmt in ('apk', 'ipk')]
        self.assertEqual(len(self.check_assets(original + beam + generic + mips)['assets']), 10)
        self.assertEqual(len(self.check_assets(original + mips)['assets']), 6)
        for invalid in (original + mips[:1], original + generic[:1], original + beam[:1], original + [original[0]], original + [('arm_cortex-a7', fmt) for fmt in ('apk', 'ipk')]):
            with self.assertRaises(ValueError):
                self.check_assets(invalid)

if __name__ == '__main__':
    unittest.main()