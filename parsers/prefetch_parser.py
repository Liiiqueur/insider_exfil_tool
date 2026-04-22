from __future__ import annotations

import ctypes
import logging
import struct
from datetime import datetime, timezone
from typing import NamedTuple

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 포맷 상수
# ──────────────────────────────────────────

_SCCA_SIGNATURE = b"SCCA"
_MAM_SIGNATURE  = 0x044D414D       # b"MAM\x04" 리틀엔디언 — Windows 10/11 압축 헤더
_MAM_HEADER_LEN = 8                 # signature(4) + decompressed_size(4)

_EXE_NAME_OFF   = 0x10
_EXE_NAME_LEN   = 60               # UTF-16LE 바이트 길이

# RtlDecompressBufferEx COMPRESSION_FORMAT: LZNT1(0x0002) + ENGINE_STANDARD(0x0100) + HUFFMAN(0x0001)
_COMPRESSION_FORMAT = 0x0104


class _VersionLayout(NamedTuple):
    run_count_offset: int
    time_offset:      int
    timestamps_count: int


_VERSION_LAYOUTS: dict[int, _VersionLayout] = {
    17: _VersionLayout(0x90, 0x78, 1),   # Windows XP
    23: _VersionLayout(0x98, 0x80, 1),   # Windows 7
    26: _VersionLayout(0xD0, 0x80, 8),   # Windows 8/8.1
    30: _VersionLayout(0xD0, 0x80, 8),   # Windows 10/11
    31: _VersionLayout(0xD0, 0x80, 8),   
    32: _VersionLayout(0xD0, 0x80, 8),
}


# ──────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────

def parse(entries: list[dict]) -> list[dict]:
    results: list[dict] = []

    for entry in entries:
        temp_path = entry.get("temp_path")
        if not temp_path:
            continue

        record = _parse_pf(temp_path, entry)
        if record is not None:
            results.append(record)

    logger.debug("prefetch_parser: %d 개 엔트리 파싱 완료", len(results))
    return results


# ──────────────────────────────────────────
# 내부 — 파일 읽기 + 압축 해제
# ──────────────────────────────────────────

def _parse_pf(temp_path: str, entry: dict) -> dict | None:
    try:
        with open(temp_path, "rb") as f:
            data = f.read()
    except OSError as e:
        logger.warning("Prefetch 파일 읽기 실패 (%s): %s", temp_path, e)
        return None

    # Windows 10/11: MAM 압축 해제 시도
    decompressed = _decompress_mam(data)
    if decompressed is not None:
        data = decompressed

    return _parse_bytes(data, entry)


def _decompress_mam(data: bytes) -> bytes | None:
    if len(data) < _MAM_HEADER_LEN:
        return None

    signature, decompressed_size = struct.unpack_from("<II", data, 0)
    if signature != _MAM_SIGNATURE:
        return None     # 압축되지 않은 파일 — 정상 경로로 진행

    compressed = data[_MAM_HEADER_LEN:]

    try:
        ntdll    = ctypes.WinDLL("ntdll.dll")
        out_buf  = ctypes.create_string_buffer(decompressed_size)
        out_size = ctypes.c_ulong(0)
        work_buf = ctypes.create_string_buffer(0x400 * 8)

        status = ntdll.RtlDecompressBufferEx(
            _COMPRESSION_FORMAT,
            out_buf,
            decompressed_size,
            compressed,
            len(compressed),
            ctypes.byref(out_size),
            work_buf,
        )
        if status != 0:
            logger.debug("RtlDecompressBufferEx 실패: NTSTATUS=0x%X", status)
            return None

        return out_buf.raw[: out_size.value]

    except Exception as e:
        logger.warning("MAM 압축 해제 실패: %s", e)
        return None


# ──────────────────────────────────────────
# 내부 — 구조체 파싱
# ──────────────────────────────────────────

def _parse_bytes(data: bytes, entry: dict) -> dict | None:
    if len(data) < _EXE_NAME_OFF + _EXE_NAME_LEN:
        logger.debug("Prefetch 파일 크기 부족: %s", entry.get("file_name"))
        return None

    version   = struct.unpack_from("<I", data, 0)[0]
    signature = data[4:8]

    logger.warning("Prefetch 파싱 시도: %s | version=%d | signature=%s",
                   entry.get("file_name"), version, signature)

    if signature != _SCCA_SIGNATURE:
        logger.debug(
            "Prefetch 시그니처 불일치 (version=%d, sig=%s): %s",
            version, signature, entry.get("file_name"),
        )
        return None

    layout = _VERSION_LAYOUTS.get(version)
    if layout is None:
        logger.debug(
            "지원하지 않는 Prefetch 버전 %d: %s", version, entry.get("file_name")
        )
        return None

    try:
        exe_name   = _read_exe_name(data)
        run_count  = _read_run_count(data, layout)
        timestamps = _read_timestamps(data, layout)
    except struct.error as e:
        logger.warning(
            "Prefetch 구조체 파싱 실패 (%s): %s", entry.get("file_name"), e
        )
        return None

    return {
        "artifact_name": "prefetch",
        "executable":    exe_name,
        "run_count":     run_count,
        "last_run_time": timestamps[0] if timestamps else None,
        "all_run_times": timestamps,
        "source_path":   entry.get("source_path"),
        "file_name":     entry.get("file_name"),
        "version":       version,
    }


def _read_exe_name(data: bytes) -> str:
    raw = data[_EXE_NAME_OFF: _EXE_NAME_OFF + _EXE_NAME_LEN]
    return raw.decode("utf-16le", errors="ignore").rstrip("\x00")


def _read_run_count(data: bytes, layout: _VersionLayout) -> int:
    return struct.unpack_from("<I", data, layout.run_count_offset)[0]


def _read_timestamps(data: bytes, layout: _VersionLayout) -> list[datetime]:
    timestamps: list[datetime] = []
    for i in range(layout.timestamps_count):
        offset = layout.time_offset + i * 8
        if offset + 8 > len(data):
            break
        raw = struct.unpack_from("<Q", data, offset)[0]
        dt  = _filetime_to_dt(raw)
        if dt is not None:
            timestamps.append(dt)
    return timestamps


def _filetime_to_dt(filetime: int) -> datetime | None:
    if not filetime:
        return None
    try:
        return datetime.fromtimestamp(
            (filetime - 116_444_736_000_000_000) / 10_000_000,
            tz=timezone.utc,
        )
    except (OSError, OverflowError, ValueError):
        return None