"""
UserAssist Collector
====================
레지스트리에서 UserAssist 항목을 원시(raw) 형태로 수집한다.

수집 경로:
  HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist

대상 GUID (Windows 7/8/10/11):
  {CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count  → 실행파일 실행 기록
  {F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Count  → 바로가기(.lnk) 실행 기록
"""

import winreg
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ── 수집 대상 GUID ────────────────────────────────────────────────────────────
USERASSIST_GUIDS = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executable",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcut",
}

BASE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"


def collect() -> list[dict]:
    """
    UserAssist Count 키 하위의 모든 값을 수집한다.

    Returns
    -------
    list[dict]
        각 항목은 다음 필드를 포함한다.
        {
            "guid"       : str   – 원본 GUID 문자열
            "guid_type"  : str   – "Executable" | "Shortcut"
            "name_rot13" : str   – ROT13 인코딩된 원본 값 이름
            "raw_data"   : bytes – 레지스트리 BINARY 값 (파싱은 parser 에서 수행)
            "collected_at": str  – ISO 8601 수집 시각
        }
    """
    results: list[dict] = []
    collected_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    for guid, guid_type in USERASSIST_GUIDS.items():
        count_key_path = f"{BASE_KEY}\\{guid}\\Count"
        try:
            hkey = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                count_key_path,
                access=winreg.KEY_READ,
            )
        except FileNotFoundError:
            logger.warning("키를 찾을 수 없음: %s", count_key_path)
            continue
        except PermissionError:
            logger.error("접근 권한 없음: %s", count_key_path)
            continue
        except Exception as exc:
            logger.exception("키 열기 실패 [%s]: %s", count_key_path, exc)
            continue

        with hkey:
            idx = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(hkey, idx)
                except OSError:
                    # 더 이상 값이 없으면 루프 종료
                    break

                # REG_BINARY 타입만 의미 있는 구조체 데이터를 가진다.
                if value_type == winreg.REG_BINARY and isinstance(value_data, bytes):
                    results.append(
                        {
                            "guid": guid,
                            "guid_type": guid_type,
                            "name_rot13": value_name,
                            "raw_data": value_data,
                            "collected_at": collected_at,
                        }
                    )
                idx += 1

    logger.info("UserAssist 수집 완료 – 총 %d 개 항목", len(results))
    return results