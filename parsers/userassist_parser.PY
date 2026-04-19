import struct
import codecs
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# Windows FILETIME epoch: 1601-01-01 00:00:00 UTC
_FILETIME_EPOCH_DELTA = 116_444_736_000_000_000  # 100-nanosecond intervals
_STRUCT_MIN_LEN = 0x44  # 최소 68 bytes 필요 (0x43까지 읽으려면 0x44 바이트)


# ── ROT13 디코딩 ──────────────────────────────────────────────────────────────

def rot13_decode(text: str) -> str:
    return codecs.decode(text, "rot_13")


# ── FILETIME 변환 ─────────────────────────────────────────────────────────────

def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    if filetime == 0:
        return None
    try:
        microseconds = (filetime - _FILETIME_EPOCH_DELTA) // 10
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + \
               __import__("datetime").timedelta(microseconds=microseconds)
    except (OverflowError, OSError, ValueError):
        return None


# ── 구조체 파싱 ───────────────────────────────────────────────────────────────

def _parse_binary(raw: bytes) -> dict:
    result = {
        "session_id": None,
        "run_count": None,
        "last_run_time": None,
        "last_run_time_raw": None,
    }

    if len(raw) < _STRUCT_MIN_LEN:
        logger.debug("binary 데이터가 너무 짧음 (%d bytes)", len(raw))
        return result

    try:
        session_id, run_count = struct.unpack_from("<II", raw, 0x00)
        filetime = struct.unpack_from("<Q", raw, 0x3C)[0]

        result["session_id"] = session_id
        # 실행 횟수: Windows 내부적으로 +1 보정 필요 (알려진 quirk)
        result["run_count"] = max(run_count - 1, 0) if run_count > 0 else 0
        result["last_run_time_raw"] = filetime
        result["last_run_time"] = filetime_to_datetime(filetime)
    except struct.error as exc:
        logger.warning("구조체 파싱 오류: %s", exc)

    return result


# ── 공개 인터페이스 ───────────────────────────────────────────────────────────

def parse(raw_entries: list[dict]) -> list[dict]:
    parsed: list[dict] = []

    for entry in raw_entries:
        raw_data: bytes = entry.get("raw_data", b"")
        name_rot13: str = entry.get("name_rot13", "")

        decoded_name = rot13_decode(name_rot13)
        binary_info = _parse_binary(raw_data)

        parsed.append(
            {
                "guid": entry.get("guid", ""),
                "guid_type": entry.get("guid_type", ""),
                "name_encoded": name_rot13,
                "name": decoded_name,
                "session_id": binary_info["session_id"],
                "run_count": binary_info["run_count"],
                "last_run_time": binary_info["last_run_time"],
                "collected_at": entry.get("collected_at", ""),
            }
        )

    # 마지막 실행 시간 내림차순 정렬 (None 은 뒤로)
    parsed.sort(
        key=lambda x: x["last_run_time"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    logger.info("UserAssist 파싱 완료 – %d 개 레코드", len(parsed))
    return parsed


def parse_to_timeline(parsed_entries: list[dict]) -> list[dict]:
    timeline: list[dict] = []

    for entry in parsed_entries:
        ts = entry.get("last_run_time")
        if ts is None:
            continue  # 실행 시간 없는 항목은 타임라인에서 제외

        timeline.append(
            {
                "timestamp": ts,
                "event_type": "program_execution",
                "source": f"UserAssist ({entry['guid_type']})",
                "description": f"프로그램 실행: {entry['name']}",
                "detail": {
                    "run_count": entry["run_count"],
                    "session_id": entry["session_id"],
                    "encoded_name": entry["name_encoded"],
                },
            }
        )

    timeline.sort(key=lambda x: x["timestamp"], reverse=True)
    return timeline