import re
from datetime import datetime, timezone

from parsers.artifact_weights import attach_artifact_weight

try:
    from Registry import Registry
    _REGISTRY_OK = True
except ImportError:
    _REGISTRY_OK = False


ROOT_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"


def _decode_recentdoc_value(raw_data: bytes, fallback: str) -> str:
    try:
        decoded = raw_data.decode("utf-16-le", errors="ignore")
        parts = [part.strip() for part in decoded.split("\x00") if part.strip()]
        if parts:
            return parts[0]
    except Exception:
        pass
    ascii_hits = [match.decode("latin-1", errors="ignore").strip() for match in re.findall(rb"[\x20-\x7E]{3,}", raw_data)]
    return ascii_hits[0] if ascii_hits else fallback


def _walk_key(key, username: str, source_path: str, collected_at: str, bucket: list[dict]):
    extension = key.name() if key.name() != "RecentDocs" else ""
    for value in key.values():
        if value.name() == "MRUListEx":
            continue
        document_name = _decode_recentdoc_value(value.raw_data(), value.name())
        bucket.append(attach_artifact_weight({"username": username, "source_path": source_path, "registry_key": key.path(), "slot": value.name(), "extension": extension, "document_name": document_name, "last_written_time": key.timestamp(), "collected_at": collected_at}, "recentdocs"))
    for subkey in key.subkeys():
        _walk_key(subkey, username, source_path, collected_at, bucket)


def parse(collected: list[dict]) -> list[dict]:
    if not _REGISTRY_OK:
        raise ImportError("python-registry is required for RecentDocs parsing")
    results = []
    for info in collected:
        reg = Registry.Registry(info["tmp_path"])
        try:
            root = reg.open(ROOT_KEY)
        except Registry.RegistryKeyNotFoundException:
            continue
        _walk_key(root, info["username"], info["source_path"], info["collected_at"], results)
    results.sort(key=lambda item: item.get("last_written_time") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for entry in entries:
        if not entry.get("last_written_time"):
            continue
        timeline.append({"timestamp": entry["last_written_time"], "event_type": "recentdocs", "source": "RecentDocs", "description": f"Recent document recorded: {entry.get('document_name')}", "detail": {"username": entry.get("username"), "registry_key": entry.get("registry_key"), "extension": entry.get("extension")}})
    return timeline
