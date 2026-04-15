from datetime import datetime, timezone

from parsers.artifact_weights import attach_artifact_weight
from parsers.jumplist_parser import parse_lnk


def parse(collected: list[dict]) -> list[dict]:
    results = []
    for info in collected:
        try:
            with open(info["tmp_path"], "rb") as stream:
                raw = stream.read()
        except OSError:
            continue
        parsed = parse_lnk(raw)
        if not parsed:
            continue
        results.append(attach_artifact_weight({**info, **parsed}, "lnk"))
    results.sort(key=lambda item: item.get("access_time") or item.get("write_time") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for entry in entries:
        ts = entry.get("access_time") or entry.get("write_time") or entry.get("creation_time")
        if not ts:
            continue
        timeline.append({
            "timestamp": ts,
            "event_type": "lnk",
            "source": "LNK",
            "description": f"Shortcut target: {entry.get('target_path') or entry.get('name') or entry.get('source_path')}",
            "detail": {"username": entry.get("username"), "lnk_location": entry.get("lnk_location"), "source_path": entry.get("source_path")},
        })
    return timeline
