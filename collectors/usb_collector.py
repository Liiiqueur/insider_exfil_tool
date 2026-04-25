from __future__ import annotations

import logging
import os
import struct
import tempfile
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 상수
# ──────────────────────────────────────────

_FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000   # 1601-01-01 → 1970-01-01 (100ns 단위)
_FILETIME_EPOCH        = datetime(1970, 1, 1, tzinfo=timezone.utc)

_DEVICE_PROP_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"

# 속성 ID(hex 소문자 4자리) → 필드명
_PROP_ID_MAP: dict[str, str] = {
    "0064": "install_time",
    "0065": "first_install_time",
    "0066": "last_arrival_time",
    "0067": "last_removal_time",
}

_SYSTEM_HIVE_CANDIDATES = (
    "/Windows/System32/config/SYSTEM",
    "/WINDOWS/system32/config/SYSTEM",
    "/windows/system32/config/SYSTEM",
)

_TIMESTAMP_FIELDS = ("install_time", "first_install_time", "last_arrival_time", "last_removal_time")


# ──────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────

def collect(hive_path: str) -> list[dict]:
    reg = _open_hive(hive_path)
    if not reg:
        return []
    controlsets = _resolve_controlsets(reg)
    return [
        *_collect_usbstor(reg, controlsets),
        *_collect_enum_usb(reg, controlsets),
    ]


def collect_from_image(handler, fs) -> list[dict]:
    for hive_path in _SYSTEM_HIVE_CANDIDATES:
        result = _try_collect_from_path(handler, fs, hive_path)
        if result is not None:
            return result

    logger.warning("USB: SYSTEM 하이브를 찾을 수 없습니다.")
    return []


# ──────────────────────────────────────────
# 내부 — 이미지 추출
# ──────────────────────────────────────────

def _try_collect_from_path(handler, fs, hive_path: str) -> list[dict] | None:
    try:
        f     = fs.open(hive_path)
        inode = f.info.meta.addr
    except Exception:
        return None

    data = handler.read_file(fs, inode, 256 * 1024 * 1024)
    if not data:
        return None

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix="_SYSTEM_hive", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        logger.debug("USB: SYSTEM hive 추출 완료 → %s (%d bytes)", tmp_path, len(data))
        return collect(tmp_path)
    except Exception as exc:
        logger.warning("USB collect_from_image 실패: %s", exc)
        return None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ──────────────────────────────────────────
# 내부 — USBSTOR 수집
# ──────────────────────────────────────────

def _collect_usbstor(reg, controlsets: list[str]) -> list[dict]:
    seen_serials: set[str] = set()
    entries: list[dict]    = []

    for controlset in controlsets:
        try:
            usbstor_root = reg.open(f"{controlset}\\Enum\\USBSTOR")
        except Exception:
            continue

        for type_key in usbstor_root.subkeys():
            type_info = _parse_usbstor_type(type_key.name())
            for serial_key in type_key.subkeys():
                serial = serial_key.name()
                if serial in seen_serials:
                    continue
                seen_serials.add(serial)
                entries.append(_build_usbstor_entry(serial_key, serial, type_info, controlset))

        break   # 현재 ControlSet 처리 후 중단

    logger.debug("USBSTOR entries collected: %d", len(entries))
    return entries


def _parse_usbstor_type(type_str: str) -> dict:
    vendor, product, revision, device_type = "", "", "", "Unknown"
    for part in type_str.split("&"):
        key, _, val = part.partition("_")
        k = key.lower()
        if   k == "disk":  device_type = "Disk"
        elif k == "cdrom": device_type = "CdRom"
        elif k == "ven":   vendor   = val
        elif k == "prod":  product  = val
        elif k == "rev":   revision = val
    return {
        "device_type_string": type_str,
        "device_type":        device_type,
        "vendor":             vendor,
        "product":            product,
        "revision":           revision,
    }


def _build_usbstor_entry(serial_key, serial: str, type_info: dict, controlset: str) -> dict:
    entry = {
        "source":          "USBSTOR",
        "controlset":      controlset,
        "serial_number":   serial,
        "is_unique_serial":not serial.startswith("&"),
        "friendly_name":   _safe_value(serial_key, "FriendlyName", ""),
        "device_desc":     _clean_inf(_safe_value(serial_key, "DeviceDesc",  "") or ""),
        "manufacturer":    _clean_inf(_safe_value(serial_key, "Mfg",         "") or ""),
        "parent_id_prefix":_safe_value(serial_key, "ParentIdPrefix", ""),
        "hardware_id":     _first_hardware_id(_safe_value(serial_key, "HardwareID", "")),
        **{f: None for f in _TIMESTAMP_FIELDS},
        **type_info,
    }
    entry.update(_read_device_timestamps(serial_key))
    return entry


# ──────────────────────────────────────────
# 내부 — Enum\USB 수집
# ──────────────────────────────────────────

def _collect_enum_usb(reg, controlsets: list[str]) -> list[dict]:
    seen: set[str]      = set()
    entries: list[dict] = []

    for controlset in controlsets:
        try:
            usb_root = reg.open(f"{controlset}\\Enum\\USB")
        except Exception:
            continue

        for vid_pid_key in usb_root.subkeys():
            vid_info = _parse_vid_pid(vid_pid_key.name())
            for serial_key in vid_pid_key.subkeys():
                serial    = serial_key.name()
                dedup_key = f"{vid_pid_key.name()}|{serial}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                entries.append(_build_enum_usb_entry(serial_key, serial, vid_info, controlset))

        break

    logger.debug("Enum\\USB entries collected: %d", len(entries))
    return entries


def _parse_vid_pid(vid_pid_str: str) -> dict:
    vid, pid, mi = "", "", ""
    for part in vid_pid_str.split("&"):
        pu = part.upper()
        if   pu.startswith("VID_"): vid = part[4:]
        elif pu.startswith("PID_"): pid = part[4:]
        elif pu.startswith("MI_"):  mi  = part[3:]
    return {
        "vid_pid_string":   vid_pid_str,
        "vendor_id":        vid,
        "product_id":       pid,
        "interface_number": mi,
    }


def _build_enum_usb_entry(serial_key, serial: str, vid_info: dict, controlset: str) -> dict:
    entry = {
        "source":          "Enum\\USB",
        "controlset":      controlset,
        "serial_number":   serial,
        "is_unique_serial":not serial.startswith("&"),
        "device_desc":     _clean_inf(_safe_value(serial_key, "DeviceDesc",  "") or ""),
        "friendly_name":   _safe_value(serial_key, "FriendlyName", ""),
        "manufacturer":    _clean_inf(_safe_value(serial_key, "Mfg",         "") or ""),
        **{f: None for f in _TIMESTAMP_FIELDS},
        **vid_info,
    }
    entry.update(_read_device_timestamps(serial_key))
    return entry


# ──────────────────────────────────────────
# 내부 — 하이브 유틸
# ──────────────────────────────────────────

def _open_hive(path: str):
    try:
        from Registry import Registry
        return Registry.Registry(path)
    except ImportError:
        logger.error("python-registry 가 설치되지 않았습니다: pip install python-registry")
        return None
    except Exception as exc:
        logger.warning("하이브 열기 실패 [%s]: %s", path, exc)
        return None


def _resolve_controlsets(reg) -> list[str]:
    ordered: list[str] = []
    try:
        current_num = reg.open("Select").value("Current").value()
        if isinstance(current_num, int) and 1 <= current_num <= 9:
            ordered.append(f"ControlSet{current_num:03d}")
    except Exception:
        pass
    for cs in ("ControlSet001", "ControlSet002", "ControlSet003"):
        if cs not in ordered:
            ordered.append(cs)
    return ordered


def _safe_value(key, name: str, default=None):
    try:
        return key.value(name).value()
    except Exception:
        return default


def _read_device_timestamps(serial_key) -> dict:
    result: dict = {}
    try:
        guid_key = serial_key.subkey("Properties").subkey(_DEVICE_PROP_GUID)
    except Exception:
        return result

    for prop_subkey in guid_key.subkeys():
        prop_id    = prop_subkey.name().lower().zfill(4)
        field_name = _PROP_ID_MAP.get(prop_id)
        if not field_name:
            continue
        for val in prop_subkey.values():
            try:
                raw = val.value()
                if isinstance(raw, bytes):
                    ts = _filetime_to_dt(raw)
                    if ts:
                        result[field_name] = ts
            except Exception:
                pass
            break   # 첫 번째 값만 읽음

    return result


# ──────────────────────────────────────────
# 내부 — 변환 유틸
# ──────────────────────────────────────────

def _filetime_to_dt(raw: bytes) -> datetime | None:
    if not raw or len(raw) < 8:
        return None
    value = struct.unpack_from("<Q", raw)[0]
    if not value:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(
            microseconds=(value - _FILETIME_EPOCH_OFFSET) // 10
        )
    except (OverflowError, OSError, ValueError):
        return None


def _clean_inf(raw: str) -> str:
    if not raw:
        return ""
    return raw.rsplit(";", 1)[-1].strip() if ";" in raw else raw.strip()


def _first_hardware_id(hw_ids) -> str:
    if isinstance(hw_ids, list):
        return hw_ids[0] if hw_ids else ""
    if isinstance(hw_ids, str):
        return hw_ids.split("\x00")[0]
    return ""