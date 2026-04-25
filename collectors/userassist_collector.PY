from __future__ import annotations

import glob
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 상수
# ──────────────────────────────────────────

# UserAssist GUID → 항목 유형 설명
USERASSIST_GUIDS: dict[str, str] = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executable",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcut",
}

_BASE_KEY = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
)

# NTUSER.DAT 탐색 패턴
_SEARCH_PATTERNS = (
    "Users/*/NTUSER.DAT",
    "Documents and Settings/*/NTUSER.DAT",
    "NTUSER.DAT",
)


# ──────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────

def collect(mount_path: str) -> list[dict]:
    all_results: list[dict] = []
    for hive_path in find_ntuser_dat_files(mount_path):
        all_results.extend(_collect_from_hive(hive_path))
    return all_results


def find_ntuser_dat_files(mount_path: str) -> list[str]:
    if mount_path.lower().endswith("ntuser.dat") and os.path.isfile(mount_path):
        return [mount_path]

    found: list[str] = []
    for pattern in _SEARCH_PATTERNS:
        full_pattern = os.path.join(mount_path, *pattern.split("/"))
        for path in glob.glob(full_pattern):
            if os.path.isfile(path):
                found.append(path)
    return found


# ──────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────

def _collect_from_hive(ntuser_path: str) -> list[dict]:
    try:
        from Registry import Registry
    except ImportError:
        raise ImportError(
            "python-registry 가 설치되지 않았습니다.\n"
            "  pip install python-registry"
        )

    try:
        reg = Registry.Registry(ntuser_path)
    except Exception as exc:
        logger.error("하이브 열기 실패 [%s]: %s", ntuser_path, exc)
        return []

    username     = _username_from_path(ntuser_path)
    collected_at = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    results: list[dict] = []

    for guid, guid_type in USERASSIST_GUIDS.items():
        results.extend(
            _collect_guid(reg, guid, guid_type, username, ntuser_path, collected_at)
        )

    return results


def _collect_guid(
    reg,
    guid: str,
    guid_type: str,
    username: str,
    ntuser_path: str,
    collected_at: str,
) -> list[dict]:
    from Registry import Registry

    key_path = f"{_BASE_KEY}\\{guid}\\Count"
    try:
        count_key = reg.open(key_path)
    except Registry.RegistryKeyNotFoundException:
        return []
    except Exception as exc:
        logger.error("[%s] 키 열기 실패 (%s): %s", username, guid, exc)
        return []

    results: list[dict] = []
    for value in count_key.values():
        if value.value_type() != Registry.RegBin:
            continue
        raw_data = value.raw_data()
        if not isinstance(raw_data, bytes):
            continue
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


def _username_from_path(ntuser_path: str) -> str:
    parts = ntuser_path.replace("\\", "/").split("/")
    # 마지막 요소가 NTUSER.DAT 이므로 그 앞이 사용자 디렉터리
    return parts[-2] if len(parts) >= 2 else "unknown"