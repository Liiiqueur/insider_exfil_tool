import re
from datetime import datetime, timezone

from parsers.artifact_weights import attach_artifact_weight

try:
    from Registry import Registry
    _REGISTRY_OK = True
except ImportError:
    _REGISTRY_OK = False


ROOT_KEYS = (
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
)


def _shell_item_name(raw_data: bytes, fallback: str) -> str:
    unicode_hits = []
    for match in re.findall(rb"(?:[\x20-\x7E]\x00){3,}", raw_data):
        text = match.decode("utf-16-le", errors="ignore").strip("\x00 ").strip()
        if text:
            unicode_hits.append(text)
    if unicode_hits:
        return unicode_hits[-1]
    ascii_hits = [match.decode("latin-1", errors="ignore") for match in re.findall(rb"[\x20-\x7E]{3,}", raw_data)]
    return ascii_hits[-1] if ascii_hits else fallback


def _walk_bagmru(key, path_parts: list[str], username: str, source_path: str, collected_at: str, bucket: list[dict]):
    for value in key.values():
        if value.name() == "MRUListEx" or value.value_type() != Registry.RegBin:
            continue
        item_name = _shell_item_name(value.raw_data(), value.name())
        full_path = "\\".join(path_parts + [item_name]).strip("\\")
        bucket.append(attach_artifact_weight({"username": username, "source_path": source_path, "registry_key": key.path(), "shell_path": full_path or item_name, "item_name": item_name, "slot": value.name(), "last_written_time": key.timestamp(), "collected_at": collected_at}, "shellbags"))
        try:
            child = key.subkey(value.name())
        except Registry.RegistryKeyNotFoundException:
            continue
        _walk_bagmru(child, path_parts + [item_name], username, source_path, collected_at, bucket)


def parse(collected: list[dict]) -> list[dict]:
    if not _REGISTRY_OK:
        raise ImportError("python-registry is required for Shellbags parsing")
    results = []
    for info in collected:
        reg = Registry.Registry(info["tmp_path"])
        for root_key in ROOT_KEYS:
            try:
                key = reg.open(root_key)
            except Registry.RegistryKeyNotFoundException:
                continue
            _walk_bagmru(key, [], info["username"], info["source_path"], info["collected_at"], results)
    results.sort(key=lambda item: item.get("last_written_time") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    return [{"timestamp": entry["last_written_time"], "event_type": "folder_access", "source": "Shellbags", "description": f"Folder access trace: {entry.get('shell_path')}", "detail": {"username": entry.get("username"), "registry_key": entry.get("registry_key")}} for entry in entries if entry.get("last_written_time")]
