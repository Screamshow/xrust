import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('packager', Path(__file__).with_name('package_openwrt.py'))
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


def elf32(fp_abi=3, flags=0x70001000):
    names = b'\0.shstrtab\0.MIPS.abiflags\0'
    abi_offset = 52 + len(names)
    attributes = bytes([0, 0, 32, 2, 1, 0, 0, fp_abi]) + bytes(16)
    section_offset = abi_offset + len(attributes)
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    header = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 8, 1, 0, 0,
                         section_offset, flags, 52, 0, 0, 40, 3, 1)
    sections = bytes(40)
    sections += struct.pack('<10I', 1, 3, 0, 0, 52, len(names), 0, 0, 1, 0)
    sections += struct.pack('<10I', 11, 0x7000002a, 0, 0, abi_offset, 24, 0, 0, 8, 24)
    return header + names + attributes + sections


class MipsElfTests(unittest.TestCase):
    def test_soft_float_mips32r2_is_accepted(self):
        packager.validate_elf(elf32(), 'mipsel', 1, 8)

    def test_hard_float_and_wrong_isa_are_rejected(self):
        for data in [elf32(fp_abi=1), elf32(flags=0x90001000), elf32(flags=0x70000000)]:
            with self.assertRaises(ValueError):
                packager.validate_elf(data, 'mipsel', 1, 8)

    def test_wrong_class_endian_and_truncation_are_rejected(self):
        baseline = elf32()
        for data in [baseline[:4] + b'\x02' + baseline[5:],
                     baseline[:5] + b'\x02' + baseline[6:], baseline[:51], baseline[:-20]]:
            with self.assertRaises(ValueError):
                packager.validate_elf(data, 'mipsel', 1, 8)


if __name__ == '__main__':
    unittest.main()
