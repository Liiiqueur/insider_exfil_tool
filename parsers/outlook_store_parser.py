import os
import logging
from datetime import datetime, timezone
from typing import Optional

from parsers.artifact_weights import attach_artifact_weight

logger = logging.getLogger(__name__)

try:
    import pypff
    _PFF_OK = True
except ImportError:
    _PFF_OK = False


def _safe_dt(value):
    if not value:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _fallback_entry(info: dict) -> dict:
    entry = {
        "username": info["username"],
        "store_type": info["store_type"],
        "filename": info["filename"],
        "source_path": info["source_path"],
        "size": info["size"],
        "display_name": os.path.splitext(info["filename"])[0],
        "message_count": None,
        "folder_count": None,
        "last_message_time": None,
        "recent_subjects": [],
        "collected_at": info["collected_at"],
    }
    return attach_artifact_weight(entry, "outlook_store")


def _walk_folder(folder, subjects: list[str], stats: dict, depth: int = 0, max_depth: int = 3):
    if depth > max_depth:
        return

    try:
        sub_messages = folder.number_of_sub_messages
    except Exception:
        sub_messages = 0

    for index in range(min(sub_messages, 25)):
        try:
            message = folder.get_sub_message(index)
        except Exception:
            continue
        stats["message_count"] += 1
        delivery_time = _safe_dt(getattr(message, "delivery_time", None))
        if delivery_time and (stats["last_message_time"] is None or delivery_time > stats["last_message_time"]):
            stats["last_message_time"] = delivery_time
        subject = getattr(message, "subject", "") or ""
        if subject and len(subjects) < 10:
            subjects.append(subject)

    try:
        sub_folders = folder.number_of_sub_folders
    except Exception:
        sub_folders = 0

    stats["folder_count"] += sub_folders
    for index in range(sub_folders):
        try:
            child = folder.get_sub_folder(index)
        except Exception:
            continue
        _walk_folder(child, subjects, stats, depth + 1, max_depth=max_depth)


def _parse_with_pff(info: dict) -> Optional[dict]:
    store = pypff.file()
    try:
        store.open(info["tmp_path"])
        root = store.get_root_folder()
        stats = {"message_count": 0, "folder_count": 0, "last_message_time": None}
        subjects: list[str] = []
        _walk_folder(root, subjects, stats)
        entry = {
            "username": info["username"],
            "store_type": info["store_type"],
            "filename": info["filename"],
            "source_path": info["source_path"],
            "size": info["size"],
            "display_name": getattr(root, "name", "") or os.path.splitext(info["filename"])[0],
            "message_count": stats["message_count"],
            "folder_count": stats["folder_count"],
            "last_message_time": stats["last_message_time"],
            "recent_subjects": subjects,
            "collected_at": info["collected_at"],
        }
        return attach_artifact_weight(entry, "outlook_store")
    except Exception as exc:
        logger.debug("pypff parse failed for %s: %s", info["filename"], exc)
        return None
    finally:
        try:
            store.close()
        except Exception:
            pass


def parse(collected: list[dict]) -> list[dict]:
    results = []
    for info in collected:
        entry = _parse_with_pff(info) if _PFF_OK else None
        results.append(entry or _fallback_entry(info))

    results.sort(key=lambda item: item.get("last_message_time") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for entry in entries:
        if not entry.get("last_message_time"):
            continue
        timeline.append({
            "timestamp": entry["last_message_time"],
            "event_type": "mailbox_activity",
            "source": f"Outlook {entry.get('store_type')}",
            "description": f"메일 저장소 최근 활동: {entry.get('filename')}",
            "detail": {
                "message_count": entry.get("message_count"),
                "recent_subjects": entry.get("recent_subjects", [])[:3],
            },
        })
    return timeline
