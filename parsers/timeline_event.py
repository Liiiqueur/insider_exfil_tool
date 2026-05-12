from __future__ import annotations

from datetime import datetime, timezone


# ──────────────────────────────────────────────────────────────
# artifact_type + action → event_type 매핑 테이블
# 키: (artifact_type, action)  값이 없으면 artifact_type 단독 매핑 시도
# ──────────────────────────────────────────────────────────────

_EXACT_MAP: dict[tuple[str, str], str] = {
    # filesystem / MFT
    ("filesystem", "created"):          "mft_created",
    ("filesystem", "modified"):         "mft_modified",
    ("filesystem", "accessed"):         "mft_accessed",
    ("filesystem", "deleted"):          "mft_modified",
    ("filesystem", "renamed"):          "mft_modified",

    # USB
    ("usb", "arrival"):                 "usb_arrival",
    ("usb", "connected"):               "usb_arrival",
    ("usb", "inserted"):                "usb_arrival",
    ("mounteddevices", "mounted"):      "usb_arrival",
    ("mounteddevices", "connected"):    "usb_arrival",

    # 브라우저
    ("browser_artifacts", "visit"):     "browser_history",
    ("browser_artifacts", "visited"):   "browser_history",
    ("browser_artifacts", "download"):  "browser_download",
    ("browser_artifacts", "downloaded"):"browser_download",

    # 프로그램 실행
    ("prefetch", "executed"):           "program_execution",
    ("prefetch", "execution"):          "program_execution",
    ("userassist", "executed"):         "program_execution",
    ("userassist", "execution"):        "program_execution",
    ("amcache", "executed"):            "program_execution",
    ("amcache", "execution"):           "program_execution",

    # 이벤트 로그
    ("eventlog", "logged"):             "eventlog_timestamp",
    ("eventlog", "recorded"):           "eventlog_timestamp",
    ("eventlog", "event"):              "eventlog_timestamp",

    # 파일 접근 계열 (LNK / RecentDocs / Jumplist / Shellbags)
    ("lnk", "accessed"):                "mft_accessed",
    ("lnk", "opened"):                  "mft_accessed",
    ("recentdocs", "accessed"):         "mft_accessed",
    ("recentdocs", "opened"):           "mft_accessed",
    ("jumplist", "accessed"):           "mft_accessed",
    ("jumplist", "opened"):             "mft_accessed",
    ("shellbags", "accessed"):          "mft_accessed",
    ("shellbags", "browsed"):           "mft_accessed",

    # 인쇄 스풀
    ("spool", "printed"):               "print_job",
    ("spool", "spooled"):               "print_job",
    ("spool", "print"):                 "print_job",

    # 메일
    ("ost_pst", "sent"):                "email_sent",
    ("ost_pst", "received"):            "email_sent",
    ("ost_pst", "email"):               "email_sent",
}

# artifact_type 만으로 결정되는 기본값 (action이 위 테이블에 없을 때 폴백)
_FALLBACK_MAP: dict[str, str] = {
    "filesystem":        "mft_modified",
    "usb":               "usb_arrival",
    "mounteddevices":    "usb_arrival",
    "browser_artifacts": "browser_history",
    "prefetch":          "program_execution",
    "userassist":        "program_execution",
    "amcache":           "program_execution",
    "eventlog":          "eventlog_timestamp",
    "lnk":               "mft_accessed",
    "recentdocs":        "mft_accessed",
    "jumplist":          "mft_accessed",
    "shellbags":         "mft_accessed",
    "spool":             "print_job",
    "ost_pst":           "email_sent",
}


def _resolve_event_type(artifact_type: str, action: str) -> str:
    """
    artifact_type + action 조합으로 behavior.py 가 기대하는
    event_type 문자열을 반환한다.
    1) (artifact_type, action) 정확 매핑 시도
    2) (artifact_type, action.lower()) 소문자 재시도
    3) artifact_type 단독 폴백
    4) 그래도 없으면 artifact_type 그대로 반환
    """
    key = (artifact_type, action)
    if key in _EXACT_MAP:
        return _EXACT_MAP[key]

    key_lower = (artifact_type, action.lower())
    if key_lower in _EXACT_MAP:
        return _EXACT_MAP[key_lower]

    return _FALLBACK_MAP.get(artifact_type, artifact_type)


# ──────────────────────────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────────────────────────

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
    event_type = _resolve_event_type(artifact_type, action)
    return {
        "timestamp":     normalized_timestamp,
        "artifact_type": artifact_type,
        "event_type":    event_type,          # ← behavior.py 가 사용하는 필드
        "action":        action,
        "target":        target,
        "source":        source or artifact_type,
        "description":   target,              # ← behavior.py 가 사용하는 필드
        "summary":       summary or _default_summary(action, target),
        "detail":        detail or {},
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