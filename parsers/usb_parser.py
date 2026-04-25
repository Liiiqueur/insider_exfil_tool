from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 상수
# ──────────────────────────────────────────

# 정제된 항목에 항상 포함되는 타임스탬프 필드
_TIMESTAMP_FIELDS = ("install_time", "first_install_time", "last_arrival_time", "last_removal_time")


# ──────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────

def parse(raw_entries: list[dict]) -> list[dict]:
    if not raw_entries:
        return []

    usbstor_raw, usbenum_raw = _split_by_source(raw_entries)
    vid_pid_lookup            = _build_vid_pid_lookup(usbenum_raw)
    usbstor_serial_norms      = {_normalize_serial(e.get("serial_number", "")) for e in usbstor_raw}

    parsed = (
        [_build_usbstor_entry(e, vid_pid_lookup) for e in usbstor_raw]
        + [
            _build_enum_usb_entry(e)
            for e in usbenum_raw
            if _normalize_serial(e.get("serial_number", "")) not in usbstor_serial_norms
        ]
    )

    parsed.sort(key=_sort_key, reverse=True)

    logger.debug(
        "USB 파싱 완료: USBSTOR %d개 + Enum\\USB 전용 %d개 = 총 %d개",
        len(usbstor_raw),
        len(parsed) - len(usbstor_raw),
        len(parsed),
    )
    return parsed


# ──────────────────────────────────────────
# 내부 — 항목 분류
# ──────────────────────────────────────────

def _split_by_source(entries: list[dict]) -> tuple[list[dict], list[dict]]:
    usbstor, usbenum = [], []
    for e in entries:
        source = e.get("source") or ""
        if "USBSTOR" in source:
            usbstor.append(e)
        elif "USB" in source:
            usbenum.append(e)
    return usbstor, usbenum


# ──────────────────────────────────────────
# 내부 — 항목 조립
# ──────────────────────────────────────────

def _build_usbstor_entry(entry: dict, vid_pid_lookup: dict) -> dict:
    serial  = entry.get("serial_number", "")
    vid_pid = vid_pid_lookup.get(_normalize_serial(serial), {})

    return {
        "artifact_source":  "USBSTOR",
        "device_type":      entry.get("device_type", ""),
        "vendor":           entry.get("vendor", ""),
        "product":          entry.get("product", ""),
        "revision":         entry.get("revision", ""),
        "serial_number":    serial,
        "is_unique_serial": entry.get("is_unique_serial", True),
        "friendly_name":    entry.get("friendly_name", ""),
        "device_desc":      entry.get("device_desc", ""),
        "manufacturer":     entry.get("manufacturer", ""),
        "parent_id_prefix": entry.get("parent_id_prefix", ""),
        "hardware_id":      entry.get("hardware_id", ""),
        # Enum\USB 역참조
        "vendor_id":        vid_pid.get("vendor_id", ""),
        "product_id":       vid_pid.get("product_id", ""),
        "vid_pid_string":   vid_pid.get("vid_pid_string", ""),
        **_pick_timestamps(entry),
    }


def _build_enum_usb_entry(entry: dict) -> dict:
    serial = entry.get("serial_number", "")
    return {
        "artifact_source":  "Enum\\USB",
        "device_type":      entry.get("device_desc", ""),
        "vendor":           entry.get("manufacturer", ""),
        "product":          entry.get("friendly_name", "") or entry.get("device_desc", ""),
        "revision":         "",
        "serial_number":    serial,
        "is_unique_serial": not serial.startswith("&"),
        "friendly_name":    entry.get("friendly_name", ""),
        "device_desc":      entry.get("device_desc", ""),
        "manufacturer":     entry.get("manufacturer", ""),
        "parent_id_prefix": "",
        "hardware_id":      "",
        "vendor_id":        entry.get("vendor_id", ""),
        "product_id":       entry.get("product_id", ""),
        "vid_pid_string":   entry.get("vid_pid_string", ""),
        **_pick_timestamps(entry),
    }


def _pick_timestamps(entry: dict) -> dict:
    return {f: entry.get(f) for f in _TIMESTAMP_FIELDS}


# ──────────────────────────────────────────
# 내부 — VID/PID 역참조 테이블
# ──────────────────────────────────────────

def _build_vid_pid_lookup(usbenum_entries: list[dict]) -> dict:
    lookup: dict[str, dict] = {}
    for entry in usbenum_entries:
        serial = _normalize_serial(entry.get("serial_number", ""))
        if not serial:
            continue
        has_mi   = bool(entry.get("interface_number"))
        existing = lookup.get(serial)
        # 아직 없거나, 기존 항목이 MI 있는데 현재 항목이 MI 없으면 교체
        if existing is None or (not has_mi and existing["_has_mi"]):
            lookup[serial] = {
                "vendor_id":      entry.get("vendor_id", ""),
                "product_id":     entry.get("product_id", ""),
                "vid_pid_string": entry.get("vid_pid_string", ""),
                "_has_mi":        has_mi,
            }
    return lookup


# ──────────────────────────────────────────
# 내부 — 정렬·시리얼 정규화 유틸
# ──────────────────────────────────────────

def _sort_key(entry: dict) -> float:
    for field in ("last_arrival_time", "first_install_time", "install_time"):
        ts = entry.get(field)
        if ts is not None and hasattr(ts, "timestamp"):
            return ts.timestamp()
    return 0.0


def _normalize_serial(serial: str) -> str:
    s = (serial or "").strip().upper()
    if s.startswith("&"):
        return s
    if "&" in s:
        s = s.split("&")[0]
    return s