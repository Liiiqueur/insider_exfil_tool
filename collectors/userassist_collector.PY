import os
import glob
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

USERASSIST_GUIDS = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executable",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcut",
}

BASE_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"


# ── NTUSER.DAT 자동 탐색 ──────────────────────────────────────────────────────

def find_ntuser_dat_files(mount_path: str) -> list[str]:
    """
    마운트 경로에서 모든 사용자의 NTUSER.DAT 경로를 반환한다.

    탐색 순서:
      1. {mount_path}\\Users\\*\\NTUSER.DAT          (Windows Vista 이상)
      2. {mount_path}\\Documents and Settings\\*\\NTUSER.DAT  (XP 이하)
      3. {mount_path}\\NTUSER.DAT                    (루트 직접 지정 시)
    """
    # NTUSER.DAT 파일을 직접 넘긴 경우
    if mount_path.lower().endswith("ntuser.dat") and os.path.isfile(mount_path):
        return [mount_path]

    found = []
    patterns = [
        os.path.join(mount_path, "Users", "*", "NTUSER.DAT"),
        os.path.join(mount_path, "Documents and Settings", "*", "NTUSER.DAT"),
        os.path.join(mount_path, "NTUSER.DAT"),
    ]
    for pattern in patterns:
        for path in glob.glob(pattern):
            if os.path.isfile(path):
                found.append(path)

    return found


# ── 단일 하이브 수집 ──────────────────────────────────────────────────────────

def _collect_from_hive(ntuser_path: str) -> list[dict]:
    """단일 NTUSER.DAT 파일에서 UserAssist 항목을 수집한다."""
    try:
        from Registry import Registry
    except ImportError:
        raise ImportError(
            "python-registry 가 설치되지 않았습니다.\n"
            "  pip install python-registry"
        )

    results = []
    collected_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    try:
        reg = Registry.Registry(ntuser_path)
    except Exception as exc:
        logger.error("하이브 열기 실패 [%s]: %s", ntuser_path, exc)
        return results

    # 사용자명: Users\<이름>\NTUSER.DAT 구조에서 추출
    parts = ntuser_path.replace("\\", "/").split("/")
    username = parts[-2] if len(parts) >= 2 else "unknown"

    for guid, guid_type in USERASSIST_GUIDS.items():
        key_path = f"{BASE_KEY}\\{guid}\\Count"
        try:
            count_key = reg.open(key_path)
        except Registry.RegistryKeyNotFoundException:
            continue
        except Exception as exc:
            logger.error("[%s] 키 열기 실패: %s", username, exc)
            continue

        for value in count_key.values():
            if value.value_type() == Registry.RegBin:
                raw_data = value.raw_data()
                if isinstance(raw_data, bytes):
                    results.append({
                        "guid":         guid,
                        "guid_type":    guid_type,
                        "name_rot13":   value.name(),
                        "raw_data":     raw_data,
                        "username":     username,
                        "hive_path":    ntuser_path,
                        "collected_at": collected_at,
                    })

    return results


# ── 공개 인터페이스 ───────────────────────────────────────────────────────────

def collect(mount_path: str) -> list[dict]:
    """
    마운트 경로 안의 모든 사용자 NTUSER.DAT 에서 UserAssist 를 수집한다.

    Parameters
    ----------
    mount_path : str
        마운트된 드라이브 루트 (예: "E:\\") 또는 NTUSER.DAT 직접 경로

    Returns
    -------
    list[dict]
        수집된 raw 항목 목록. 각 항목:
        {
            "guid"        : str
            "guid_type"   : str    – "Executable" | "Shortcut"
            "name_rot13"  : str    – ROT13 인코딩된 원본 값 이름
            "raw_data"    : bytes  – REG_BINARY 원시 데이터
            "username"    : str    – NTUSER.DAT 소유 사용자명
            "hive_path"   : str    – 원본 하이브 파일 경로
            "collected_at": str    – ISO 8601 수집 시각
        }
    """
    hive_files = find_ntuser_dat_files(mount_path)

    if not hive_files:
        return []

    all_results = []
    for hive_path in hive_files:
        results = _collect_from_hive(hive_path)
        all_results.extend(results)
    return all_results
