from __future__ import annotations

import logging
import struct
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 상수
# ──────────────────────────────────────────

_FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000   # 1601-01-01 → 1970-01-01 (100ns)
_FILETIME_EPOCH        = datetime(1970, 1, 1, tzinfo=timezone.utc)

# SHD 구조체 오프셋
_OFF_JOB_ID     = 0x00
_OFF_USER_PTR   = 0x10
_OFF_DOC_PTR    = 0x14
_OFF_TIMESTAMP  = 0x18

_SHD_MIN_LEN    = _OFF_TIMESTAMP + 8   # 타임스탬프까지 읽으려면 최소 0x20 bytes


# ──────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────

def parse(entries: list[dict]) -> list[dict]:
    results: list[dict] = []

    for entry in entries:
        if entry.get("file_type") != "SHD":
            continue

        temp_path = entry.get("temp_path")
        if not temp_path:
            continue

        record = _parse_shd(temp_path, entry)
        if record is not None:
            results.append(record)

    logger.debug("spool_parser: %d 개 SHD 파싱 완료", len(results))
    return results


# ──────────────────────────────────────────
# 내부 — 파일 읽기
# ──────────────────────────────────────────

def _parse_shd(temp_path: str, entry: dict) -> dict | None:
    try:
        with open(temp_path, "rb") as f:
            data = f.read()
    except OSError as e:
        logger.warning("SHD 파일 읽기 실패 (%s): %s", temp_path, e)
        return None

    return _parse_bytes(data, entry)


def _parse_bytes(data: bytes, entry: dict) -> dict | None:
    if len(data) < _SHD_MIN_LEN:
        logger.debug(
            "SHD 파일 크기 부족 (%d bytes): %s", len(data), entry.get("file_name")
        )
        return None

    try:
        job_id      = struct.unpack_from("<I", data, _OFF_JOB_ID)[0]
        user_offset = struct.unpack_from("<I", data, _OFF_USER_PTR)[0]
        doc_offset  = struct.unpack_from("<I", data, _OFF_DOC_PTR)[0]
        time_raw    = struct.unpack_from("<Q", data, _OFF_TIMESTAMP)[0]
    except struct.error as e:
        logger.warning("SHD 구조체 파싱 실패 (%s): %s", entry.get("file_name"), e)
        return None

    return {
        "artifact_name": "spool",
        "job_id":        job_id,
        "user":          _read_utf16(data, user_offset),
        "document_name": _read_utf16(data, doc_offset),
        "timestamp":     _filetime_to_dt(time_raw),
        "source_path":   entry.get("source_path"),
        "file_name":     entry.get("file_name"),
    }


# ──────────────────────────────────────────
# 내부 — 변환 유틸
# ──────────────────────────────────────────

def _read_utf16(data: bytes, offset: int) -> str:
    if offset == 0 or offset >= len(data):
        return ""
    chunk = data[offset:]
    end   = chunk.find(b"\x00\x00")
    raw   = chunk[:end] if end != -1 else chunk
    # UTF-16LE 는 2바이트 단위이므로 홀수 바이트면 마지막 1바이트 제거
    if len(raw) % 2:
        raw = raw[:-1]
    return raw.decode("utf-16le", errors="ignore")


def _filetime_to_dt(filetime: int) -> datetime | None:
    if not filetime:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(
            microseconds=(filetime - _FILETIME_EPOCH_OFFSET) // 10
        )
    except (OverflowError, OSError, ValueError):
        return None