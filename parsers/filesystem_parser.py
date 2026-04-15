import os
from datetime import datetime, timezone

from parsers.artifact_weights import attach_artifact_weight


def _raw_artifact_entry(info: dict) -> dict:
    try:
        size = os.path.getsize(info["tmp_path"]) if info.get("tmp_path") else None
    except OSError:
        size = None
    return attach_artifact_weight({
        "artifact_name": info["artifact_name"],
        "record_type": "raw_artifact",
        "source_path": info["source_path"],
        "size": size,
        "collected_at": info["collected_at"],
    }, "filesystem")


def _mft_record_entry(info: dict) -> dict:
    return attach_artifact_weight({
        "artifact_name": "$MFT",
        "record_type": "filesystem_record",
        "source_path": info["source_path"],
        "entry_name": info.get("entry_name"),
        "is_dir": bool(info.get("is_dir")),
        "inode": info.get("inode"),
        "size": info.get("size"),
        "created_time": info.get("created_time"),
        "modified_time": info.get("modified_time"),
        "accessed_time": info.get("accessed_time"),
        "changed_time": info.get("changed_time"),
        "collected_at": info.get("collected_at"),
    }, "filesystem")


def parse(collected: list[dict]) -> list[dict]:
    results = []
    for info in collected:
        if info.get("record_type") == "filesystem_record":
            results.append(_mft_record_entry(info))
        else:
            results.append(_raw_artifact_entry(info))
    results.sort(
        key=lambda item: item.get("accessed_time") or item.get("modified_time") or item.get("created_time") or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    results.sort(key=lambda item: 0 if item.get("artifact_name") == "$MFT" and item.get("record_type") == "filesystem_record" else 1)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for entry in entries:
        if entry.get("artifact_name") != "$MFT" or entry.get("record_type") != "filesystem_record":
            continue
        for field_name, event_type, label in (
            ("created_time", "mft_created", "Created"),
            ("modified_time", "mft_modified", "Modified"),
            ("accessed_time", "mft_accessed", "Accessed"),
            ("changed_time", "mft_changed", "Changed"),
        ):
            timestamp = entry.get(field_name)
            if not timestamp:
                continue
            timeline.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "source": "$MFT",
                "description": f"{label}: {entry.get('source_path')}",
                "detail": {
                    "inode": entry.get("inode"),
                    "size": entry.get("size"),
                    "is_dir": entry.get("is_dir"),
                },
            })
    timeline.sort(key=lambda item: item["timestamp"], reverse=True)
    return timeline
