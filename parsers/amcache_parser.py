from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────
# 서브키별 extractor 함수
# ──────────────────────────────────────────

def _extract_inventory_application_file(subkey, values: dict, source_path: str) -> dict:
    return {
        "artifact_name": "amcache",
        "subkey_type":   "InventoryApplicationFile",
        "file_path":     values.get("LowerCaseLongPath", ""),
        "file_name":     values.get("Name", ""),
        "sha1":          _strip_sha1_prefix(values.get("FileId", "")
                         or values.get("Sha1", "")),
        "size":          values.get("Size", ""),
        "publisher":     values.get("Publisher", ""),
        "product":       values.get("ProductName", ""),
        "version":       values.get("Version", ""),
        "compile_time":  values.get("LinkDate", ""),
        "last_modified": _to_utc(subkey.timestamp()),
        "source_path":   source_path,
    }


def _extract_inventory_application(subkey, values: dict, source_path: str) -> dict:
    return {
        "artifact_name": "amcache",
        "subkey_type":   "InventoryApplication",
        "file_name":     values.get("Name", ""),
        "publisher":     values.get("Publisher", ""),
        "version":       values.get("Version", ""),
        "install_date":  values.get("InstallDate", ""),
        "install_path":  values.get("InstallLocation", ""),
        "uninstall_key": values.get("UninstallString", ""),
        "last_modified": _to_utc(subkey.timestamp()),
        "source_path":   source_path,
    }


def _extract_inventory_driver_binary(subkey, values: dict, source_path: str) -> dict:
    return {
        "artifact_name":  "amcache",
        "subkey_type":    "InventoryDriverBinary",
        "file_name":      values.get("DriverName", ""),
        "driver_id":      subkey.name(),
        "sha1":           _strip_sha1_prefix(values.get("DriverCheckSum", "")),
        "driver_version": values.get("DriverVersion", ""),
        "driver_company": values.get("DriverCompany", ""),
        "last_modified":  _to_utc(subkey.timestamp()),
        "source_path":    source_path,
    }


def _extract_inventory_device_container(subkey, values: dict, source_path: str) -> dict:
    return {
        "artifact_name":   "amcache",
        "subkey_type":     "InventoryDeviceContainer",
        "file_name":       values.get("FriendlyName", ""),
        "publisher":       values.get("Manufacturer", ""),
        "device_category": values.get("Category", ""),
        "model_name":      values.get("ModelName", ""),
        "model_number":    values.get("ModelNumber", ""),
        "last_modified":   _to_utc(subkey.timestamp()),
        "source_path":     source_path,
    }


def _extract_inventory_device_pnp(subkey, values: dict, source_path: str) -> dict:
    return {
        "artifact_name": "amcache",
        "subkey_type":   "InventoryDevicePnp",
        "file_name":     values.get("FriendlyName", "") or values.get("Description", ""),
        "publisher":     values.get("Manufacturer", ""),
        "device_id":     values.get("DeviceId", ""),
        "class_name":    values.get("Class", ""),
        "driver_id":     values.get("Driver", ""),
        "last_modified": _to_utc(subkey.timestamp()),
        "source_path":   source_path,
    }


def _extract_inventory_application_shortcut(subkey, values: dict, source_path: str) -> dict:
    return {
        "artifact_name": "amcache",
        "subkey_type":   "ApplicationShortcut",
        "file_path":     values.get("ShortCutPath", ""),
        "last_modified": _to_utc(subkey.timestamp()),
        "source_path":   source_path,
    }


def _extract_legacy_file(subkey, values: dict, source_path: str) -> dict:
    return {
        "artifact_name": "amcache",
        "subkey_type":   "LegacyFile",
        "file_path":     values.get("15", ""),
        "sha1":          _strip_sha1_prefix(values.get("101", "")),
        "compile_time":  values.get("f", ""),
        "last_modified": _to_utc(subkey.timestamp()),
        "source_path":   source_path,
    }


# (key_path, extractor)  — Root\ 를 제거한 상대 경로로 hive.open() 에 전달
_SUBKEY_HANDLERS: list[tuple[str, callable]] = [
    (r"Root\InventoryApplicationFile",      _extract_inventory_application_file),
    (r"Root\InventoryApplication",          _extract_inventory_application),
    (r"Root\InventoryDriverBinary",         _extract_inventory_driver_binary),
    (r"Root\InventoryDeviceContainer",      _extract_inventory_device_container),
    (r"Root\InventoryDevicePnp",            _extract_inventory_device_pnp),
    (r"Root\InventoryApplicationShortcut",  _extract_inventory_application_shortcut),
    (r"Root\File",                          _extract_legacy_file),
]


# ──────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────

def parse(entries: list[dict]) -> list[dict]:
    results: list[dict] = []

    for entry in entries:
        temp_path = entry.get("temp_path")
        if not temp_path:
            continue
        _parse_hive(temp_path, entry.get("source_path", ""), results)

    logger.debug("amcache_parser: 총 %d 개 엔트리 파싱 완료", len(results))
    return results


# ──────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────

def _parse_hive(temp_path: str, source_path: str, results: list[dict]) -> None:
    try:
        from Registry import Registry
        hive = Registry.Registry(temp_path)
    except Exception as e:
        logger.warning(
            "hive 열기 실패 (%s): [%s] %r", temp_path, type(e).__name__, e
        )
        return
    
    root = hive.root()
    logger.warning("hive root key: '%s'", root.name())
    logger.warning("root subkeys: %s", [k.name() for k in root.subkeys()])

   
    for key_path, extractor in _SUBKEY_HANDLERS:
        _parse_subkey(hive, key_path, extractor, source_path, results)


def _parse_subkey(
    hive,
    key_path: str,
    extractor,
    source_path: str,
    results: list[dict],
) -> None:
    from Registry import Registry

    try:
        key = hive.open(key_path)
    except Registry.RegistryKeyNotFoundException:
        # 해당 버전 Windows 에 없는 서브키면 조용히 건너뜀
        return
    except Exception as e:
        logger.debug("서브키 열기 실패 [%s]: %s", key_path, e)
        return

    for subkey in key.subkeys():
        try:
            values = {v.name(): v.value() for v in subkey.values()}
            record = extractor(subkey, values, source_path)
            if record:
                results.append(record)
        except Exception as e:
            logger.debug(
                "서브키 파싱 실패 [%s\\%s]: %s", key_path, subkey.name(), e
            )


def _to_utc(ts: datetime | None) -> datetime | None:
    if ts is None:
        return None
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)


def _strip_sha1_prefix(value: str) -> str:
    if not value:
        return value
    if value.startswith("0000") and len(value) > 4:
        return value[4:]
    return value