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
    """
    ROT13 디코딩. Python 내장 codecs 를 사용한다.
    비알파벳 문자(숫자, 특수문자, 경로 구분자 등)는 변환되지 않는다.
    """
    return codecs.decode(text, "rot_13")


# ── FILETIME 변환 ─────────────────────────────────────────────────────────────

def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """
    Windows FILETIME (100-nanosecond intervals since 1601-01-01) →
    timezone-aware datetime (UTC).

    값이 0 이면 None 반환 (기록 없음).
    """
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
    """
    REG_BINARY 값을 파싱해 session, run_count, last_run_time 을 추출한다.
    데이터가 짧거나 손상된 경우 None 으로 채운다.
    """
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
    """
    collector.collect() 결과를 받아 파싱된 레코드 목록을 반환한다.

    Parameters
    ----------
    raw_entries : list[dict]
        userassist_collector.collect() 의 반환값

    Returns
    -------
    list[dict]
        파싱된 항목 목록. 각 항목:
        {
            "guid"          : str
            "guid_type"     : str           – "Executable" | "Shortcut"
            "name_encoded"  : str           – ROT13 인코딩된 원본 이름
            "name"          : str           – 디코딩된 실행 경로/이름
            "session_id"    : int | None
            "run_count"     : int | None
            "last_run_time" : datetime | None  (UTC, timezone-aware)
            "collected_at"  : str
        }
    """
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
    """
    파싱된 UserAssist 레코드를 타임라인 통합 형식으로 변환한다.

    타임라인 공통 스키마:
        timestamp  : datetime (UTC)
        event_type : str
        source     : str
        description: str
        detail     : dict
    """
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