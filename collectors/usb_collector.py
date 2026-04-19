import logging
import os
import struct
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ─── 상수 ──────────────────────────────────────────────────────────────────────

# Windows FILETIME 에포크 오프셋: 1601-01-01 ~ 1970-01-01 (100ns 단위)
_FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000

# 타임스탬프 속성 GUID (장치 설치 날짜/시간)
_DEVICE_PROP_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"

# 속성 ID → 필드명 매핑 (hex 소문자)
_PROP_ID_MAP = {
    "0064": "install_time",         # 최초 드라이버 설치 일시
    "0065": "first_install_time",   # 최초 연결 일시 (Windows 8+)
    "0066": "last_arrival_time",    # 마지막 연결(Arrival) 일시
    "0067": "last_removal_time",    # 마지막 제거(Removal) 일시
}

# SYSTEM 하이브 후보 경로 (pytsk3 경로 표기)
_SYSTEM_HIVE_CANDIDATES = [
    "/Windows/System32/config/SYSTEM",
    "/WINDOWS/system32/config/SYSTEM",
    "/windows/system32/config/SYSTEM",
]


# ─── 내부 유틸리티 ─────────────────────────────────────────────────────────────

def _filetime_to_dt(raw: bytes) -> Optional[datetime]:
    if not raw or len(raw) < 8:
        return None
    value = struct.unpack_from("<Q", raw)[0]
    if value == 0:
        return None
    try:
        microseconds = (value - _FILETIME_EPOCH_OFFSET) // 10
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)
    except (OverflowError, OSError, ValueError):
        return None


def _open_hive(path: str):
    try:
        from Registry import Registry
        return Registry.Registry(path)
    except ImportError:
        logger.error("python-registry가 설치되지 않았습니다: pip install python-registry")
        return None
    except Exception as exc:
        logger.warning("하이브 열기 실패 [%s]: %s", path, exc)
        return None


def _safe_value(key, name: str, default=None):
    try:
        return key.value(name).value()
    except Exception:
        return default


def _clean_inf_string(raw: str) -> str:
    if not raw:
        return ""
    if ";" in raw:
        return raw.rsplit(";", 1)[-1].strip()
    return raw.strip()


def _resolve_controlsets(reg) -> list:
    ordered = []
    try:
        select_key = reg.open("Select")
        current_num = _safe_value(select_key, "Current", 1)
        if isinstance(current_num, int) and 1 <= current_num <= 9:
            ordered.append(f"ControlSet{current_num:03d}")
    except Exception:
        pass
    for cs in ["ControlSet001", "ControlSet002", "ControlSet003"]:
        if cs not in ordered:
            ordered.append(cs)
    return ordered


def _read_device_timestamps(serial_key) -> dict:
    result = {}
    try:
        # Properties 키 탐색 (1단계씩 내려가야 함 - subkey()는 단일 계층만 허용)
        props_key = serial_key.subkey("Properties")
        guid_key = props_key.subkey(_DEVICE_PROP_GUID)
    except Exception:
        return result

    for prop_subkey in guid_key.subkeys():
        prop_id = prop_subkey.name().lower().zfill(4)  # "64" → "0064" 정규화
        field_name = _PROP_ID_MAP.get(prop_id)
        if not field_name:
            continue
        # 해당 prop_id 하위 키의 첫 번째 값을 REG_BINARY로 읽음
        for val in prop_subkey.values():
            try:
                raw = val.value()
                if isinstance(raw, bytes):
                    ts = _filetime_to_dt(raw)
                    if ts:
                        result[field_name] = ts
            except Exception:
                pass
            break  # 첫 번째 값만 읽음

    return result


def _parse_hardware_id(hw_ids) -> str:
    if isinstance(hw_ids, list):
        return hw_ids[0] if hw_ids else ""
    if isinstance(hw_ids, str):
        return hw_ids.split("\x00")[0]
    return ""


# ─── USBSTOR 수집 ──────────────────────────────────────────────────────────────

def collect_usbstor(hive_path: str) -> list:
    reg = _open_hive(hive_path)
    if not reg:
        return []

    entries = []
    seen_serials: set = set()  # 중복 ControlSet 방지

    for controlset in _resolve_controlsets(reg):
        try:
            usbstor_root = reg.open(f"{controlset}\\Enum\\USBSTOR")
        except Exception:
            continue

        for type_key in usbstor_root.subkeys():
            # 타입 문자열 파싱: "Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP"
            type_str = type_key.name()
            vendor, product, revision, device_type = "", "", "", "Unknown"
            for part in type_str.split("&"):
                key_part, _, val_part = part.partition("_")
                k = key_part.lower()
                if k == "disk":
                    device_type = "Disk"
                elif k == "cdrom":
                    device_type = "CdRom"
                elif k == "ven":
                    vendor = val_part
                elif k == "prod":
                    product = val_part
                elif k == "rev":
                    revision = val_part

            for serial_key in type_key.subkeys():
                serial = serial_key.name()

                # 동일 시리얼이 여러 ControlSet에 중복될 수 있음 → 첫 번째만 수집
                if serial in seen_serials:
                    continue
                seen_serials.add(serial)

                entry = {
                    "source": "USBSTOR",
                    "controlset": controlset,
                    # 장치 식별
                    "device_type_string": type_str,
                    "device_type": device_type,
                    "vendor": vendor,
                    "product": product,
                    "revision": revision,
                    "serial_number": serial,
                    "is_unique_serial": not serial.startswith("&"),
                    # 장치 설명
                    "friendly_name": _safe_value(serial_key, "FriendlyName", ""),
                    "device_desc": _clean_inf_string(
                        _safe_value(serial_key, "DeviceDesc", "") or ""
                    ),
                    "manufacturer": _clean_inf_string(
                        _safe_value(serial_key, "Mfg", "") or ""
                    ),
                    # MountedDevices 교차 참조 키 (드라이브 문자 매핑에 활용)
                    "parent_id_prefix": _safe_value(serial_key, "ParentIdPrefix", ""),
                    "hardware_id": _parse_hardware_id(
                        _safe_value(serial_key, "HardwareID", "")
                    ),
                    # 타임스탬프 (기본값 None, 아래에서 채움)
                    "install_time": None,
                    "first_install_time": None,
                    "last_arrival_time": None,
                    "last_removal_time": None,
                }
                entry.update(_read_device_timestamps(serial_key))
                entries.append(entry)

        break  # 현재 ControlSet 처리 후 중단 (이미 중복 필터링됨)

    logger.debug("USBSTOR entries collected: %d", len(entries))
    return entries


# ─── Enum\USB 수집 ─────────────────────────────────────────────────────────────

def collect_enum_usb(hive_path: str) -> list:
    reg = _open_hive(hive_path)
    if not reg:
        return []

    entries = []
    seen: set = set()

    for controlset in _resolve_controlsets(reg):
        try:
            usb_root = reg.open(f"{controlset}\\Enum\\USB")
        except Exception:
            continue

        for vid_pid_key in usb_root.subkeys():
            vid_pid_str = vid_pid_key.name()  # "VID_090C&PID_1000"
            vid, pid, mi = "", "", ""
            for part in vid_pid_str.split("&"):
                pu = part.upper()
                if pu.startswith("VID_"):
                    vid = part[4:]
                elif pu.startswith("PID_"):
                    pid = part[4:]
                elif pu.startswith("MI_"):
                    mi = part[3:]

            for serial_key in vid_pid_key.subkeys():
                serial = serial_key.name()
                dedup_key = f"{vid_pid_str}|{serial}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                entry = {
                    "source": "Enum\\USB",
                    "controlset": controlset,
                    "vid_pid_string": vid_pid_str,
                    "vendor_id": vid,
                    "product_id": pid,
                    "interface_number": mi,
                    "serial_number": serial,
                    "is_unique_serial": not serial.startswith("&"),
                    "device_desc": _clean_inf_string(
                        _safe_value(serial_key, "DeviceDesc", "") or ""
                    ),
                    "friendly_name": _safe_value(serial_key, "FriendlyName", ""),
                    "manufacturer": _clean_inf_string(
                        _safe_value(serial_key, "Mfg", "") or ""
                    ),
                    "install_time": None,
                    "first_install_time": None,
                    "last_arrival_time": None,
                    "last_removal_time": None,
                }
                entry.update(_read_device_timestamps(serial_key))
                entries.append(entry)

        break

    logger.debug("Enum\\USB entries collected: %d", len(entries))
    return entries


# ─── 공개 인터페이스 ───────────────────────────────────────────────────────────

def collect(hive_path: str) -> list:
    results = []
    results.extend(collect_usbstor(hive_path))
    results.extend(collect_enum_usb(hive_path))
    return results


def collect_from_image(handler, fs) -> list:
    for hive_path in _SYSTEM_HIVE_CANDIDATES:
        inode = None
        try:
            f = fs.open(hive_path)
            inode = f.info.meta.addr
        except Exception:
            continue

        # SYSTEM 하이브는 수십 MB 이상일 수 있음 → 최대 256MB 허용
        data = handler.read_file(fs, inode, 256 * 1024 * 1024)
        if not data:
            continue

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix="_SYSTEM_hive", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            logger.debug("USB: SYSTEM hive extracted to %s (%d bytes)", tmp_path, len(data))
            return collect(tmp_path)
        except Exception as exc:
            logger.warning("USB collect_from_image 실패: %s", exc)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    logger.warning("USB: SYSTEM 하이브를 찾을 수 없습니다.")
    return []