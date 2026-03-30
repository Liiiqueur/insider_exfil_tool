"""
test_userassist.py
==================
Windows 환경이 없어도 파서 로직을 검증할 수 있는 단위 테스트.

실행:
    python test_userassist.py
"""

import struct
import unittest
from datetime import datetime, timezone

# 테스트를 위해 parser만 직접 임포트 (collector는 winreg 필요)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "parsers"))

from userassist_parser import rot13_decode, filetime_to_datetime, parse


def _make_raw(session_id: int, run_count: int, filetime: int) -> bytes:
    """테스트용 72-byte REG_BINARY 생성"""
    buf = bytearray(72)
    struct.pack_into("<II", buf, 0x00, session_id, run_count)
    struct.pack_into("<Q", buf, 0x3C, filetime)
    return bytes(buf)


# 알려진 FILETIME 값: 2024-01-15 10:30:00 UTC
# filetime = (unix_ts + 11644473600) * 10_000_000
_TS_2024 = (1705314600 + 11_644_473_600) * 10_000_000


class TestROT13(unittest.TestCase):
    def test_known_value(self):
        encoded = r"{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\BcgvbanySrngherf.rkr"
        decoded = rot13_decode(encoded)
        self.assertEqual(
            decoded,
            r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\OptionalFeatures.exe",
        )

    def test_numbers_unchanged(self):
        self.assertEqual(rot13_decode("123ABC"), "123NOP")

    def test_idempotent(self):
        # ROT13 두 번 적용하면 원문 복원
        original = r"C:\Windows\System32\calc.exe"
        self.assertEqual(rot13_decode(rot13_decode(original)), original)


class TestFiletime(unittest.TestCase):
    def test_zero_returns_none(self):
        self.assertIsNone(filetime_to_datetime(0))

    def test_known_timestamp(self):
        dt = filetime_to_datetime(_TS_2024)
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 15)

    def test_timezone_aware(self):
        dt = filetime_to_datetime(_TS_2024)
        self.assertIsNotNone(dt.tzinfo)


class TestParse(unittest.TestCase):
    def _make_entry(self, name_rot13: str, session: int, count: int, ft: int) -> dict:
        return {
            "guid": "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            "guid_type": "Executable",
            "name_rot13": name_rot13,
            "raw_data": _make_raw(session, count, ft),
            "collected_at": "2024-06-01T00:00:00Z",
        }

    def test_parse_single_entry(self):
        encoded = r"{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\BcgvbanySrngherf.rkr"
        entries = [self._make_entry(encoded, session=1, count=6, ft=_TS_2024)]
        result = parse(entries)

        self.assertEqual(len(result), 1)
        r = result[0]
        self.assertIn("OptionalFeatures.exe", r["name"])
        self.assertEqual(r["session_id"], 1)
        # run_count quirk: 저장값 - 1
        self.assertEqual(r["run_count"], 5)
        self.assertIsInstance(r["last_run_time"], datetime)

    def test_sorted_by_last_run_time(self):
        ft_old = (_TS_2024 - 10_000_000_000)
        ft_new = _TS_2024
        entries = [
            self._make_entry("byq.rkr", 1, 2, ft_old),
            self._make_entry("arj.rkr", 1, 3, ft_new),
        ]
        result = parse(entries)
        # 최신 항목이 앞에 와야 한다
        self.assertGreater(result[0]["last_run_time"], result[1]["last_run_time"])

    def test_short_binary_returns_none_fields(self):
        entry = {
            "guid": "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            "guid_type": "Executable",
            "name_rot13": "grfg.rkr",
            "raw_data": b"\x00" * 4,   # 너무 짧음
            "collected_at": "2024-06-01T00:00:00Z",
        }
        result = parse([entry])
        self.assertIsNone(result[0]["session_id"])
        self.assertIsNone(result[0]["run_count"])
        self.assertIsNone(result[0]["last_run_time"])


if __name__ == "__main__":
    unittest.main(verbosity=2)