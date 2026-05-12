from __future__ import annotations

import hashlib
import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 상수
# ──────────────────────────────────────────

_DEFAULT_TIME_WINDOW = timedelta(minutes=5)
_FALLBACK_DT         = datetime.min.replace(tzinfo=timezone.utc)

# 경로 기반 상관관계를 적용할 이벤트 타입
_PATH_EVENT_TYPES = frozenset({
    "mft_created", "mft_modified", "mft_accessed", "mft_changed",
    "lnk", "browser_download", "program_execution",
    "registry_write", "registry_delete",
})

# 실행 파일명 기반 상관관계를 적용할 이벤트 타입
_NAME_EVENT_TYPES = frozenset({
    "program_execution",
})

# 사용자 계정 기반 상관관계를 적용할 이벤트 타입
_USER_EVENT_TYPES = frozenset({
    "eventlog_timestamp", "program_execution",
    "registry_write", "registry_delete",
    "mft_created", "mft_modified",
})

# 시간 근접 상관관계: (선행 이벤트 타입, 후행 이벤트 타입, 설명)
_PROXIMITY_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("usb_arrival",       "mft_created",        "USB 연결 후 파일 생성"),
    ("usb_arrival",       "mft_modified",        "USB 연결 후 파일 수정"),
    ("usb_arrival",       "browser_history",     "USB 연결 후 브라우저 접속"),
    ("browser_history",   "mft_created",         "브라우저 접속 후 파일 생성"),
    ("browser_download",  "mft_created",         "브라우저 다운로드 후 파일 생성"),
    ("program_execution", "mft_created",         "프로그램 실행 후 파일 생성"),
    ("program_execution", "mft_modified",        "프로그램 실행 후 파일 수정"),
    ("program_execution", "registry_write",      "프로그램 실행 후 레지스트리 변경"),
    ("eventlog_timestamp","usb_arrival",          "로그온 후 USB 연결"),
    ("eventlog_timestamp","browser_history",      "로그온 후 브라우저 접속"),
    ("registry_write",    "program_execution",   "레지스트리 변경 후 프로그램 실행"),
    ("mft_created",       "browser_history",     "파일 생성 후 브라우저 접속"),
)

# 신뢰도 임계값: 관여 소스 수 기준
_CONFIDENCE_THRESHOLDS = {"high": 3, "medium": 2}

# chain 상관관계: 경로 일치 + 시간 근접 동시 만족 시 적용
_CHAIN_TIME_WINDOW = timedelta(minutes=10)


# ──────────────────────────────────────────
# 데이터 클래스
# ──────────────────────────────────────────

@dataclass
class Correlation:
    correlation_id:   str
    correlation_type: str   # "path_match" | "name_match" | "user_match" | "time_proximity" | "chain"
    confidence:       str   # "high" | "medium" | "low"
    description:      str
    events:           list[dict]
    anchor_time:      datetime | None
    metadata:         dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "correlation_id":   self.correlation_id,
            "correlation_type": self.correlation_type,
            "confidence":       self.confidence,
            "description":      self.description,
            "events":           self.events,
            "anchor_time":      self.anchor_time,
            "event_count":      len(self.events),
            "sources":          sorted({e.get("source", "") for e in self.events}),
            "metadata":         self.metadata,
        }


# ──────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────

def correlate(
    timeline: list[dict],
    time_window: timedelta = _DEFAULT_TIME_WINDOW,
) -> list[Correlation]:
    if not timeline:
        return []

    results: list[Correlation] = []
    results.extend(correlate_path(timeline))
    results.extend(correlate_name(timeline))
    results.extend(correlate_user(timeline))
    results.extend(correlate_time_proximity(timeline, time_window))
    results.extend(correlate_chain(timeline, _CHAIN_TIME_WINDOW))

    # 중복 제거
    seen:   set[str]          = set()
    unique: list[Correlation] = []
    for c in results:
        if c.correlation_id not in seen:
            seen.add(c.correlation_id)
            unique.append(c)

    unique.sort(key=lambda c: _to_utc(c.anchor_time), reverse=True)

    logger.info(
        "correlator: path=%d name=%d user=%d proximity=%d chain=%d → unique=%d",
        sum(1 for c in unique if c.correlation_type == "path_match"),
        sum(1 for c in unique if c.correlation_type == "name_match"),
        sum(1 for c in unique if c.correlation_type == "user_match"),
        sum(1 for c in unique if c.correlation_type == "time_proximity"),
        sum(1 for c in unique if c.correlation_type == "chain"),
        len(unique),
    )
    return unique


# ── 1. 파일 경로 일치 ────────────────────────────────────────────────────────

def correlate_path(timeline: list[dict]) -> list[Correlation]:
    path_groups: dict[str, list[dict]] = defaultdict(list)

    for event in timeline:
        if event.get("event_type") not in _PATH_EVENT_TYPES:
            continue
        path = _extract_path(event)
        if not path:
            continue
        path_groups[_normalize_path(path)].append(event)

    correlations: list[Correlation] = []
    for norm_path, events in path_groups.items():
        sources = {e.get("source", "") for e in events}
        if len(sources) < 2:
            continue
        correlations.append(Correlation(
            correlation_id   = _make_id("path", norm_path),
            correlation_type = "path_match",
            confidence       = _calc_confidence(sources),
            description      = f"파일 경로 다중 아티팩트 참조: {norm_path}",
            events           = _sort_events(events),
            anchor_time      = _earliest_time(events),
            metadata         = {"normalized_path": norm_path, "sources": sorted(sources)},
        ))

    return correlations


# ── 2. 실행 파일명 일치 ──────────────────────────────────────────────────────

def correlate_name(timeline: list[dict]) -> list[Correlation]:
    name_groups: dict[str, list[dict]] = defaultdict(list)

    for event in timeline:
        if event.get("event_type") not in _NAME_EVENT_TYPES:
            continue
        exe_name = _extract_exe_name(event)
        if not exe_name:
            continue
        name_groups[exe_name.upper()].append(event)

    correlations: list[Correlation] = []
    for exe_name, events in name_groups.items():
        sources = {e.get("source", "") for e in events}
        if len(sources) < 2:
            continue
        correlations.append(Correlation(
            correlation_id   = _make_id("name", exe_name),
            correlation_type = "name_match",
            confidence       = _calc_confidence(sources),
            description      = f"실행 파일 다중 소스 확인: {exe_name}",
            events           = _sort_events(events),
            anchor_time      = _earliest_time(events),
            metadata         = {"exe_name": exe_name, "sources": sorted(sources)},
        ))

    return correlations


# ── 3. 사용자 계정 일치 ──────────────────────────────────────────────────────

def correlate_user(timeline: list[dict]) -> list[Correlation]:
    user_groups: dict[str, list[dict]] = defaultdict(list)

    for event in timeline:
        if event.get("event_type") not in _USER_EVENT_TYPES:
            continue
        username = _extract_username(event)
        if not username:
            continue
        user_groups[username.lower()].append(event)

    correlations: list[Correlation] = []
    for username, events in user_groups.items():
        sources = {e.get("source", "") for e in events}
        if len(sources) < 2:
            continue
        event_types = {e.get("event_type", "") for e in events}
        correlations.append(Correlation(
            correlation_id   = _make_id("user", username),
            correlation_type = "user_match",
            confidence       = _calc_confidence(sources),
            description      = f"사용자 '{username}' 다중 아티팩트 활동",
            events           = _sort_events(events),
            anchor_time      = _earliest_time(events),
            metadata         = {
                "username":    username,
                "sources":     sorted(sources),
                "event_types": sorted(event_types),
            },
        ))

    return correlations


# ── 4. 시간 근접 ─────────────────────────────────────────────────────────────

def correlate_time_proximity(
    timeline: list[dict],
    window: timedelta = _DEFAULT_TIME_WINDOW,
) -> list[Correlation]:
    type_index: dict[str, list[dict]] = defaultdict(list)
    for event in timeline:
        et = event.get("event_type", "")
        if et:
            type_index[et].append(event)

    correlations: list[Correlation] = []

    for src_type, tgt_type, desc_template in _PROXIMITY_PAIRS:
        src_events = type_index.get(src_type, [])
        tgt_events = type_index.get(tgt_type, [])
        if not src_events or not tgt_events:
            continue

        for src_event in src_events:
            src_ts = _to_utc(src_event.get("timestamp"))
            if src_ts == _FALLBACK_DT:
                continue

            nearby: list[dict] = []
            for tgt in tgt_events:
                tgt_ts = _to_utc(tgt.get("timestamp"))
                if tgt_ts == _FALLBACK_DT:
                    continue
                diff = tgt_ts - src_ts
                if timedelta(0) <= diff <= window:
                    nearby.append(tgt)

            if not nearby:
                continue

            paired = [src_event, *nearby]
            correlations.append(Correlation(
                correlation_id   = _make_id(
                    "proximity",
                    f"{src_type}_{tgt_type}_{src_ts.isoformat()}",
                ),
                correlation_type = "time_proximity",
                confidence       = _calc_confidence(
                    {e.get("source", "") for e in paired}
                ),
                description      = (
                    f"{desc_template} "
                    f"({window.seconds // 60}분 이내, {len(nearby)}건)"
                ),
                events           = _sort_events(paired),
                anchor_time      = src_ts,
                metadata         = {
                    "src_type":     src_type,
                    "tgt_type":     tgt_type,
                    "window_min":   window.seconds // 60,
                    "nearby_count": len(nearby),
                },
            ))

    return correlations


# ── 5. 체인 상관관계 (경로 + 시간 근접 복합) ────────────────────────────────

def correlate_chain(
    timeline: list[dict],
    window: timedelta = _CHAIN_TIME_WINDOW,
) -> list[Correlation]:
    path_groups: dict[str, list[dict]] = defaultdict(list)
    for event in timeline:
        if event.get("event_type") not in _PATH_EVENT_TYPES:
            continue
        path = _extract_path(event)
        if not path:
            continue
        path_groups[_normalize_path(path)].append(event)

    correlations: list[Correlation] = []
    for norm_path, events in path_groups.items():
        sources = {e.get("source", "") for e in events}
        if len(sources) < 2:
            continue

        # 시간 창 안에 묶이는 서브그룹 탐색
        sorted_evs = _sort_events(events)
        i = 0
        while i < len(sorted_evs):
            anchor_ts = _to_utc(sorted_evs[i].get("timestamp"))
            group = [
                e for e in sorted_evs[i:]
                if _to_utc(e.get("timestamp")) - anchor_ts <= window
            ]
            if len(group) >= 2 and len({e.get("source", "") for e in group}) >= 2:
                correlations.append(Correlation(
                    correlation_id   = _make_id(
                        "chain",
                        norm_path,
                        anchor_ts.isoformat(),
                    ),
                    correlation_type = "chain",
                    confidence       = _calc_confidence(
                        {e.get("source", "") for e in group}
                    ),
                    description      = (
                        f"파일 활동 체인: {norm_path} "
                        f"({len(group)}개 이벤트, {window.seconds // 60}분 내)"
                    ),
                    events           = group,
                    anchor_time      = anchor_ts,
                    metadata         = {
                        "normalized_path": norm_path,
                        "chain_length":    len(group),
                        "sources":         sorted({e.get("source", "") for e in group}),
                    },
                ))
            i += len(group) if len(group) > 1 else 1

    return correlations


# ──────────────────────────────────────────
# 내부 — 타임스탬프
# ──────────────────────────────────────────

def _to_utc(ts) -> datetime:
    if not isinstance(ts, datetime):
        return _FALLBACK_DT
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


# ──────────────────────────────────────────
# 내부 — 경로·이름·사용자 추출
# ──────────────────────────────────────────

def _extract_path(event: dict) -> str:
    detail = event.get("detail") or {}
    for key in ("source_path", "path", "download_path", "target_path", "file_path"):
        val = event.get(key) or detail.get(key)
        if val and isinstance(val, str):
            return val
    desc = event.get("description", "")
    if ": " in desc:
        candidate = desc.split(": ", 1)[1].strip()
        if candidate.startswith("/") or (len(candidate) > 2 and candidate[1] == ":"):
            return candidate
    return ""


def _extract_exe_name(event: dict) -> str:
    detail = event.get("detail") or {}
    desc   = event.get("description", "")
    if ": " in desc:
        candidate = desc.split(": ", 1)[1].strip()
        if candidate.upper().endswith(".EXE"):
            return os.path.basename(candidate)
    for key in ("executable", "name", "process_name"):
        val = detail.get(key) or event.get(key)
        if val and isinstance(val, str):
            return os.path.basename(val)
    return ""


def _extract_username(event: dict) -> str:
    detail = event.get("detail") or {}
    for key in ("username", "user", "account_name", "subject_user_name"):
        val = detail.get(key) or event.get(key)
        if val and isinstance(val, str) and val not in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-"}:
            return val
    return ""


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lower().rstrip("/")


# ──────────────────────────────────────────
# 내부 — 범용 유틸
# ──────────────────────────────────────────

def _make_id(*parts: str) -> str:
    raw = "|".join(parts)
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:12]


def _calc_confidence(sources: set[str]) -> str:
    count = len(sources)
    if count >= _CONFIDENCE_THRESHOLDS["high"]:
        return "high"
    if count >= _CONFIDENCE_THRESHOLDS["medium"]:
        return "medium"
    return "low"


def _earliest_time(events: list[dict]) -> datetime:
    timestamps = [_to_utc(e.get("timestamp")) for e in events]
    valid = [ts for ts in timestamps if ts != _FALLBACK_DT]
    return min(valid) if valid else _FALLBACK_DT


def _sort_events(events: list[dict]) -> list[dict]:
    return sorted(events, key=lambda e: _to_utc(e.get("timestamp")))