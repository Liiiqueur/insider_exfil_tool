from __future__ import annotations

from datetime import datetime, timezone


def build_timeline_event(
    *,
    timestamp: datetime,
    artifact_type: str,
    action: str,
    target: str,
    detail: dict | None = None,
    source: str = "",
    summary: str = "",
) -> dict:
    normalized_timestamp = normalize_timestamp(timestamp)
    return {
        "timestamp": normalized_timestamp,
        "artifact_type": artifact_type,
        "action": action,
        "target": target,
        "source": source or artifact_type,
        "summary": summary or _default_summary(action, target),
        "detail": detail or {},
    }


def sort_timeline(events: list[dict]) -> list[dict]:
    events.sort(
        key=lambda item: normalize_timestamp(item["timestamp"]),
        reverse=True,
    )
    return events


def normalize_timestamp(timestamp: datetime) -> datetime:
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def make_target(*values) -> str:
    for value in values:
        if value:
            return str(value)
    return ""


def _default_summary(action: str, target: str) -> str:
    if target:
        return f"{action}: {target}"
    return action
