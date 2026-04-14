from datetime import datetime, timezone

from parsers.artifact_weights import attach_artifact_weight

try:
    from Registry import Registry
    _REGISTRY_OK = True
except ImportError:
    _REGISTRY_OK = False


VALUE_CANDIDATES = {
    "path": ("LowerCaseLongPath", "LongPath", "Path", "FullPath", "15"),
    "sha1": ("Sha1", "SHA1", "101"),
    "size": ("Size", "6"),
    "product": ("ProductName", "0"),
    "publisher": ("Publisher", "1"),
    "version": ("Version", "2"),
}


def _value_lookup(key, names: tuple[str, ...]):
    for value in key.values():
        if value.name() in names:
            return value.value()
    return None


def _walk_keys(key, bucket: list[dict], source_path: str, collected_at: str):
    children = key.subkeys()
    if not children:
        path = _value_lookup(key, VALUE_CANDIDATES["path"])
        sha1 = _value_lookup(key, VALUE_CANDIDATES["sha1"])
        product = _value_lookup(key, VALUE_CANDIDATES["product"])
        publisher = _value_lookup(key, VALUE_CANDIDATES["publisher"])
        version = _value_lookup(key, VALUE_CANDIDATES["version"])
        size = _value_lookup(key, VALUE_CANDIDATES["size"])

        if path or sha1 or product:
            entry = {
                "source_path": source_path,
                "registry_key": key.path(),
                "program_name": product or key.name(),
                "file_path": path,
                "sha1": sha1,
                "publisher": publisher,
                "version": version,
                "size": size,
                "key_timestamp": key.timestamp(),
                "collected_at": collected_at,
            }
            bucket.append(attach_artifact_weight(entry, "amcache"))
        return

    for child in children:
        _walk_keys(child, bucket, source_path, collected_at)


def parse(collected: list[dict]) -> list[dict]:
    if not _REGISTRY_OK:
        raise ImportError("python-registry is required for Amcache parsing")

    results = []
    for info in collected:
        reg = Registry.Registry(info["tmp_path"])
        for root_path in ("Root\\File", "Root\\InventoryApplicationFile", "InventoryApplicationFile"):
            try:
                root = reg.open(root_path)
            except Registry.RegistryKeyNotFoundException:
                continue
            _walk_keys(root, results, info["source_path"], info["collected_at"])

    results.sort(key=lambda item: item.get("key_timestamp") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for entry in entries:
        ts = entry.get("key_timestamp")
        if not ts:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        timeline.append({
            "timestamp": ts,
            "event_type": "program_inventory",
            "source": "Amcache",
            "description": f"프로그램/파일 등록 흔적: {entry.get('program_name')}",
            "detail": {
                "file_path": entry.get("file_path"),
                "sha1": entry.get("sha1"),
            },
        })
    return timeline
