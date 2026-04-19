import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ─── 내부 유틸리티 ─────────────────────────────────────────────────────────────

def _normalize_serial(serial: str) -> str:
    s = (serial or "").strip().upper()
    # '&'로 시작하는 비고유 시리얼은 그대로 유지 (접미사 제거 대상 아님)
    if s.startswith("&"):
        return s
    # 접미사 제거: "ABCDE1234&0" → "ABCDE1234"
    if "&" in s:
        s = s.split("&")[0]
    return s


def _build_vid_pid_lookup(usbenum_entries: list) -> dict:
    lookup: dict = {}
    for entry in usbenum_entries:
        if entry.get("source") != "Enum\\USB":
            continue
        serial = entry.get("serial_number", "")
        norm = _normalize_serial(serial)
        if not norm:
            continue
        # MI_XX 없는 항목 우선 (복합 인터페이스에서 기본 장치가 더 대표적)
        existing = lookup.get(norm)
        has_mi = bool(entry.get("interface_number"))
        if existing is None or (not has_mi and existing.get("_has_mi", True)):
            lookup[norm] = {
                "vendor_id": entry.get("vendor_id", ""),
                "product_id": entry.get("product_id", ""),
                "vid_pid_string": entry.get("vid_pid_string", ""),
                "_has_mi": has_mi,
            }
    return lookup


def _pick_best_timestamp(*candidates: Optional[datetime]) -> Optional[datetime]:
    for ts in candidates:
        if ts is not None:
            return ts
    return None


def _sort_key(entry: dict) -> float:
    ts = _pick_best_timestamp(
        entry.get("last_arrival_time"),
        entry.get("first_install_time"),
        entry.get("install_time"),
    )
    if ts and hasattr(ts, "timestamp"):
        return ts.timestamp()
    return 0.0


# ─── 공개 인터페이스 ───────────────────────────────────────────────────────────

def parse(raw_entries: list) -> list:
    if not raw_entries:
        return []

    # source별 분리
    usbstor_raw = [
        e for e in raw_entries
        if "USBSTOR" in (e.get("source") or "")
    ]

    usbenum_raw = [
        e for e in raw_entries
        if "USB" in (e.get("source") or "") and "STOR" not in (e.get("source") or "")
    ]

    # VID/PID 역참조 테이블
    vid_pid_lookup = _build_vid_pid_lookup(usbenum_raw)

    parsed: list = []

    # ── USBSTOR 항목 파싱 ──────────────────────────────────────────────────────
    for entry in usbstor_raw:
        serial = entry.get("serial_number", "")
        norm_serial = _normalize_serial(serial)
        vid_pid = vid_pid_lookup.get(norm_serial, {})

        parsed.append({
            "artifact_source": "USBSTOR",
            # 장치 식별
            "device_type": entry.get("device_type", ""),
            "vendor": entry.get("vendor", ""),
            "product": entry.get("product", ""),
            "revision": entry.get("revision", ""),
            "serial_number": serial,
            "is_unique_serial": entry.get("is_unique_serial", True),
            # 이름/설명
            "friendly_name": entry.get("friendly_name", ""),
            "device_desc": entry.get("device_desc", ""),
            "manufacturer": entry.get("manufacturer", ""),
            # 교차 참조 키
            "parent_id_prefix": entry.get("parent_id_prefix", ""),
            "hardware_id": entry.get("hardware_id", ""),
            # Enum\USB에서 보완된 VID/PID
            "vendor_id": vid_pid.get("vendor_id", ""),
            "product_id": vid_pid.get("product_id", ""),
            "vid_pid_string": vid_pid.get("vid_pid_string", ""),
            # 타임스탬프
            "install_time": entry.get("install_time"),
            "first_install_time": entry.get("first_install_time"),
            "last_arrival_time": entry.get("last_arrival_time"),
            "last_removal_time": entry.get("last_removal_time"),
        })

    # ── Enum\USB 전용 항목 (USBSTOR에 없는 비저장장치) ─────────────────────────
    usbstor_serial_norms = {
        _normalize_serial(e.get("serial_number", ""))
        for e in usbstor_raw
    }
    for entry in usbenum_raw:
        serial = entry.get("serial_number", "")
        # USBSTOR와 중복되는 항목 건너뜀 (이미 위에서 더 풍부하게 처리됨)
        if _normalize_serial(serial) in usbstor_serial_norms:
            continue

        # 비저장 USB 장치 (HID, Hub, 프린터, 카메라 등)
        parsed.append({
            "artifact_source": "Enum\\USB",
            "device_type": entry.get("device_desc", ""),
            "vendor": entry.get("manufacturer", ""),
            "product": entry.get("friendly_name", "") or entry.get("device_desc", ""),
            "revision": "",
            "serial_number": serial,
            "is_unique_serial": not serial.startswith("&"),
            "friendly_name": entry.get("friendly_name", ""),
            "device_desc": entry.get("device_desc", ""),
            "manufacturer": entry.get("manufacturer", ""),
            "parent_id_prefix": "",
            "hardware_id": "",
            "vendor_id": entry.get("vendor_id", ""),
            "product_id": entry.get("product_id", ""),
            "vid_pid_string": entry.get("vid_pid_string", ""),
            "install_time": entry.get("install_time"),
            "first_install_time": entry.get("first_install_time"),
            "last_arrival_time": entry.get("last_arrival_time"),
            "last_removal_time": entry.get("last_removal_time"),
        })

    # ── 정렬: last_arrival_time 내림차순 (가장 최근 연결 장치 최상단) ────────────
    parsed.sort(key=_sort_key, reverse=True)

    logger.debug(
        "USB 파싱 완료: USBSTOR %d개 + Enum\\USB 전용 %d개 = 총 %d개",
        len(usbstor_raw),
        len(parsed) - len(usbstor_raw),
        len(parsed),
    )
    return parsed
    