from regipy.registry import RegistryHive
from datetime import datetime, timezone


def _ts_to_dt(ts):
    if not ts:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def parse(entries):
    results = []

    for entry in entries:
        try:
            hive = RegistryHive(entry["temp_path"])

            # Windows 10+
            key_path = r"Root\InventoryApplicationFile"

            try:
                key = hive.get_key(key_path)
            except Exception:
                continue

            for subkey in key.iter_subkeys():
                values = {v.name: v.value for v in subkey.iter_values()}

                results.append({
                    "artifact_name": "amcache",
                    "file_path": values.get("LowerCaseLongPath", ""),
                    "file_name": values.get("Name", ""),
                    "sha1": values.get("Sha1", ""),
                    "size": values.get("Size", ""),
                    "publisher": values.get("Publisher", ""),
                    "product": values.get("ProductName", ""),
                    "version": values.get("Version", ""),
                    "compile_time": values.get("LinkDate", ""),
                    "last_modified": _ts_to_dt(subkey.last_modified),
                    "source_path": entry.get("source_path"),
                })

        except Exception:
            continue

    return results