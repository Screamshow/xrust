import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('finalizer', Path(__file__).with_name('finalize_release.py'))
finalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finalizer)

class OpenWrtArchitectures(unittest.TestCase):
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