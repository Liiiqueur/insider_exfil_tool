"""
USB Device Artifact Collector
==============================
오프라인 SYSTEM 하이브에서 USB 장치 흔적을 수집합니다.

수집 대상 레지스트리 경로:
  SYSTEM\\ControlSetXXX\\Enum\\USBSTOR
      USB 저장장치(USB Mass Storage)의 연결 이력 및 장치 메타데이터.
      하위 구조:
        └─ {DeviceType}&Ven_{vendor}&Prod_{product}&Rev_{rev}
              └─ {SerialNumber}
                    ├─ FriendlyName      (REG_SZ)   예: "Samsung USB Flash Drive"
                    ├─ DeviceDesc        (REG_SZ)   예: "USB 대용량 저장 장치"
                    ├─ Mfg              (REG_SZ)   제조사 문자열
                    ├─ ParentIdPrefix   (REG_SZ)   MountedDevices 교차 참조 키
                    ├─ HardwareID       (REG_MULTI_SZ)
                    └─ Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\
                          ├─ 0064  (REG_BINARY, 8 bytes FILETIME) InstallDate
                          ├─ 0065  (REG_BINARY, 8 bytes FILETIME) FirstInstallDate (Win8+)
                          ├─ 0066  (REG_BINARY, 8 bytes FILETIME) LastArrivalDate
                          └─ 0067  (REG_BINARY, 8 bytes FILETIME) LastRemovalDate

  SYSTEM\\ControlSetXXX\\Enum\\USB
      시스템에 연결된 모든 USB 장치(허브, HID, 저장장치 등).
      하위 구조:
        └─ VID_{xxxx}&PID_{xxxx}[&MI_{xx}]
              └─ {SerialNumber}
                    ├─ DeviceDesc / FriendlyName / Mfg
                    └─ Properties\\{83da6326...}\\  (위와 동일)

타임스탬프 GUID: {83da6326-97a6-4088-9453-a1923f573b29}
  - 0064 (hex) = 100 (dec) = DEVPKEY_Device_InstallDate
  - 0065 (hex) = 101 (dec) = DEVPKEY_Device_FirstInstallDate
  - 0066 (hex) = 102 (dec) = DEVPKEY_Device_LastArrivalDate
  - 0067 (hex) = 103 (dec) = DEVPKEY_Device_LastRemovalDate
"""

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
    """
    8바이트 리틀엔디언 FILETIME → UTC datetime 변환.

    FILETIME은 1601-01-01 00:00:00 UTC를 기준으로 100ns 단위의 64비트 정수.
    값이 0이면 None 반환.
    """
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
    """python-registry로 오프라인 레지스트리 하이브를 엽니다."""
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
    """레지스트리 값 안전 읽기. 예외 발생 시 default 반환."""
    try:
        return key.value(name).value()
    except Exception:
        return default


def _clean_inf_string(raw: str) -> str:
    """
    INF 리소스 문자열 접두사 제거.
    예: "@oem5.inf,%string.desc%;USB 대용량 저장 장치"
        → "USB 대용량 저장 장치"
    """
    if not raw:
        return ""
    if ";" in raw:
        return raw.rsplit(";", 1)[-1].strip()
    return raw.strip()


def _resolve_controlsets(reg) -> list:
    """
    SYSTEM 하이브의 Select\\Current 값을 읽어 우선 파싱할
    ControlSet 이름 목록을 반환합니다.

    예: Current=1 → ["ControlSet001", "ControlSet002", "ControlSet003"]
    """
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
    """
    장치 시리얼 키의 Properties\\{GUID}\\{prop_id} 하위 키에서
    FILETIME 타임스탬프 4종을 읽어 dict로 반환합니다.

    반환 키: install_time, first_install_time, last_arrival_time, last_removal_time
    """
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
    """HardwareID (REG_MULTI_SZ 또는 REG_SZ)에서 첫 번째 항목 추출."""
    if isinstance(hw_ids, list):
        return hw_ids[0] if hw_ids else ""
    if isinstance(hw_ids, str):
        return hw_ids.split("\x00")[0]
    return ""


# ─── USBSTOR 수집 ──────────────────────────────────────────────────────────────

def collect_usbstor(hive_path: str) -> list:
    """
    SYSTEM\\ControlSetXXX\\Enum\\USBSTOR 에서 USB 저장장치 항목 수집.

    USBSTOR 하위의 디바이스 타입 키 이름 형식:
      Disk&Ven_{vendor}&Prod_{product}&Rev_{revision}
      또는 CdRom&Ven_...

    시리얼 번호 앞에 '&' 가 붙으면 OS가 생성한 비고유 식별자 (장치 자체 시리얼 없음).
    """
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
    """
    SYSTEM\\ControlSetXXX\\Enum\\USB 에서 모든 USB 장치 항목 수집.

    VID/PID 키 이름 형식:
      VID_XXXX&PID_XXXX           (단일 인터페이스 장치)
      VID_XXXX&PID_XXXX&MI_XX     (복합 인터페이스 장치의 특정 인터페이스)

    주요 활용: USBSTOR 항목의 VID/PID 교차 참조, 비저장 USB 장치(HID, Hub 등) 탐지.
    """
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
    """
    단일 SYSTEM 하이브 파일에서 USBSTOR + Enum\\USB 항목을 모두 수집합니다.
    파서(usb_parser.parse)에 넘길 raw 데이터 리스트를 반환합니다.
    """
    results = []
    results.extend(collect_usbstor(hive_path))
    results.extend(collect_enum_usb(hive_path))
    return results


def collect_from_image(handler, fs) -> list:
    """
    pytsk3 파일시스템 객체(fs)에서 SYSTEM 하이브를 찾아 읽고,
    임시 파일에 기록한 뒤 collect()를 호출합니다.

    ImageHandler.read_file()로 하이브 전체를 메모리에 읽어오므로
    잠금(locked) 상태인 라이브 시스템 파일도 접근 가능합니다.
    """
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