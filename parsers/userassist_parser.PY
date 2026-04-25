from __future__ import annotations

import codecs
import struct
import logging
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 상수
# ──────────────────────────────────────────

# Windows FILETIME 기준: 1601-01-01 00:00:00 UTC
_FILETIME_EPOCH_DELTA = 116_444_736_000_000_000
_FILETIME_EPOCH       = datetime(1970, 1, 1, tzinfo=timezone.utc)

# UserAssist 바이너리 구조체 최소 길이 (0x3C + 8 bytes = 0x44)
_STRUCT_MIN_LEN = 0x44

# 구조체 오프셋
_OFF_SESSION_RUN = 0x00   # session_id(4) + run_count(4)
_OFF_FILETIME    = 0x3C   # FILETIME(8)


# ──────────────────────────────────────────
# 내부 타입
# ──────────────────────────────────────────

class _BinaryInfo(NamedTuple):
    session_id:       int | None
    run_count:        int | None
    last_run_time:    datetime | None
    last_run_time_raw:int | None


# ──────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────

def parse(raw_entries: list[dict]) -> list[dict]:
    parsed = [_parse_entry(entry) for entry in raw_entries]
    parsed.sort(
        key=lambda x: x["last_run_time"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    logger.info("UserAssist 파싱 완료 – %d 개 레코드", len(parsed))
    return parsed


def parse_to_timeline(parsed_entries: list[dict]) -> list[dict]:
    timeline = [
        _to_timeline_event(entry)
        for entry in parsed_entries
        if entry.get("last_run_time") is not None
    ]
    timeline.sort(key=lambda x: x["timestamp"], reverse=True)
    return timeline


# ──────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────

def _parse_entry(entry: dict) -> dict:
    name_rot13 = entry.get("name_rot13", "")
    info       = _parse_binary(entry.get("raw_data", b""))

    return {
        "guid":          entry.get("guid", ""),
        "guid_type":     entry.get("guid_type", ""),
        "name_encoded":  name_rot13,
        "name":          _rot13(name_rot13),
        "username":      entry.get("username", ""),
        "session_id":    info.session_id,
        "run_count":     info.run_count,
        "last_run_time": info.last_run_time,
        "collected_at":  entry.get("collected_at", ""),
    }


def _to_timeline_event(entry: dict) -> dict:
    return {
        "timestamp":  entry["last_run_time"],
        "event_type": "program_execution",
        "source":     f"UserAssist ({entry['guid_type']})",
        "description":f"프로그램 실행: {entry['name']}",
        "detail": {
            "run_count":    entry["run_count"],
            "session_id":   entry["session_id"],
            "encoded_name": entry["name_encoded"],
        },
    }


def _parse_binary(raw: bytes) -> _BinaryInfo:
    _empty = _BinaryInfo(None, None, None, None)

    if len(raw) < _STRUCT_MIN_LEN:
        logger.debug("binary 데이터가 너무 짧음 (%d bytes)", len(raw))
        return _empty

    try:
        session_id, run_count_raw = struct.unpack_from("<II", raw, _OFF_SESSION_RUN)
        filetime                  = struct.unpack_from("<Q",  raw, _OFF_FILETIME)[0]
    except struct.error as exc:
        logger.warning("구조체 파싱 오류: %s", exc)
        return _empty

    # Windows 내부적으로 run_count 에 +1 이 저장됨
    run_count = max(run_count_raw - 1, 0) if run_count_raw > 0 else 0

    return _BinaryInfo(
        session_id        = session_id,
        run_count         = run_count,
        last_run_time     = _filetime_to_dt(filetime),
        last_run_time_raw = filetime,
    )


def _filetime_to_dt(filetime: int) -> datetime | None:
    if not filetime:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=(filetime - _FILETIME_EPOCH_DELTA) // 10)
    except (OverflowError, OSError, ValueError):
        return None


def _rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")