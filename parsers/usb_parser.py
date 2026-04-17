import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ─── 내부 유틸리티 ─────────────────────────────────────────────────────────────

def _normalize_serial(serial: str) -> str:
    """
    시리얼 번호를 정규화하여 USBSTOR ↔ Enum\\USB 교차 참조 키로 사용.

    Windows는 동일 장치라도 복합 인터페이스(MI_XX)의 경우
    시리얼 뒤에 '&0', '&1' 등의 접미사를 붙이는 경우가 있으므로 제거.
    """
    s = (serial or "").strip().upper()
    # '&'로 시작하는 비고유 시리얼은 그대로 유지 (접미사 제거 대상 아님)
    if s.startswith("&"):
        return s
    # 접미사 제거: "ABCDE1234&0" → "ABCDE1234"
    if "&" in s:
        s = s.split("&")[0]
    return s


def _build_vid_pid_lookup(usbenum_entries: list) -> dict:
    """
    Enum\\USB 항목에서 정규화된 시리얼 → {vendor_id, product_id, vid_pid_string}
    역참조 테이블을 구성합니다.

    복합 인터페이스 장치(MI_XX)의 경우 여러 항목이 같은 시리얼을 공유하므로
    MI 없는 항목(기본 인터페이스)을 우선 선택합니다.
    """
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
    """여러 타임스탬프 후보 중 None이 아닌 첫 번째 값 반환."""
    for ts in candidates:
        if ts is not None:
            return ts
    return None


def _sort_key(entry: dict) -> float:
    """정렬용 숫자 키: last_arrival → first_install → install 순 우선."""
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
    """
    usb_collector.collect()의 반환값을 받아 정제된 항목 목록을 반환합니다.

    최종 항목 구조 (공통 필드):
      artifact_source      : "USBSTOR" 또는 "Enum\\USB"
      device_type          : 장치 유형 ("Disk", "CdRom", "Unknown" 등)
      vendor               : 제조사 문자열 (USBSTOR의 Ven_ 부분 또는 Mfg 값)
      product              : 제품명 (USBSTOR의 Prod_ 부분 또는 FriendlyName)
      revision             : 펌웨어 리비전 (USBSTOR의 Rev_ 부분)
      serial_number        : 장치 시리얼 번호 (원본)
      is_unique_serial     : 고유 시리얼 여부 (False면 추적 불가)
      friendly_name        : Windows가 표시하는 장치 이름
      device_desc          : 장치 클래스 설명
      manufacturer         : Mfg 레지스트리 값
      parent_id_prefix     : MountedDevices 교차 참조 키 (USBSTOR만)
      hardware_id          : HardwareID 첫 번째 항목 (USBSTOR만)
      vendor_id            : USB VID (4자리 hex, Enum\\USB에서 가져옴)
      product_id           : USB PID (4자리 hex, Enum\\USB에서 가져옴)
      vid_pid_string       : "VID_XXXX&PID_XXXX" 전체 문자열
      install_time         : 드라이버 최초 설치 일시 (Properties 0064)
      first_install_time   : 장치 최초 연결 일시 (Properties 0065, Win8+)
      last_arrival_time    : 마지막 연결 일시 (Properties 0066)
      last_removal_time    : 마지막 제거 일시 (Properties 0067)
    """
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
    