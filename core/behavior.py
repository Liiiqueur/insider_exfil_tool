from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 상수
# ──────────────────────────────────────────

# 업무 외 시간 (로컬 시각 기준 — UTC 오프셋은 진단 시 보정)
_AFTER_HOURS_START = 22   # 22:00
_AFTER_HOURS_END   = 6    # 06:00

# 대량 파일 접근 임계값 (N분 창 내)
_MASS_ACCESS_WINDOW    = timedelta(minutes=60)
_MASS_ACCESS_THRESHOLD = 30    # 파일 수

# USB 연결 후 파일 생성 창
_USB_FILE_WINDOW    = timedelta(minutes=10)
_USB_FILE_THRESHOLD = 5   # 생성 파일 수

# 인쇄 후 USB 연결 창
_PRINT_USB_WINDOW = timedelta(minutes=30)

# 로그인 실패 임계값
_LOGON_FAIL_WINDOW    = timedelta(minutes=10)
_LOGON_FAIL_THRESHOLD = 5

# 대용량 첨부 임계값 (bytes)
_LARGE_ATTACHMENT_SIZE = 5 * 1024 * 1024   # 5 MB

# 압축 파일 확장자
_ARCHIVE_EXTS = frozenset({".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"})

# 클라우드 스토리지 도메인
_CLOUD_DOMAINS = frozenset({
    "dropbox.com", "drive.google.com", "onedrive.live.com",
    "wetransfer.com", "mega.nz", "mega.co.nz", "box.com",
    "mediafire.com", "sendspace.com", "gofile.io",
    "sharepoint.com", "1drv.ms",
})

# 의심 도구 키워드 (실행파일명 포함 여부)
_SUSPICIOUS_TOOLS = frozenset({
    "filezilla", "winscp", "putty", "pscp",
    "rclone", "robocopy", "xcopy",
    "7z", "winrar", "winzip",
    "teamviewer", "anydesk", "ultraviewer",
    "wget", "curl",
    "netcat", "nc",
    "mimikatz", "procdump",
})

# 민감 문서 키워드 (인쇄 문서명 포함 여부)
_SENSITIVE_KEYWORDS = frozenset({
    "confidential", "secret", "classified", "internal",
    "비밀", "기밀", "내부", "대외비", "restricted",
    "contract", "계약", "salary", "급여", "personal",
})


# ──────────────────────────────────────────
# 데이터 클래스
# ──────────────────────────────────────────

@dataclass
class BehaviorPattern:
    pattern_id:     str
    name:           str
    risk_level:     str          # "critical" | "high" | "medium" | "low"
    description:    str
    evidence:       list[str]    # 사람이 읽을 수 있는 근거 문장
    matched_events: list[dict]   # 패턴과 매칭된 타임라인 이벤트
    detected_at:    datetime     # 패턴 내 가장 이른 이벤트 시각

    def to_dict(self) -> dict:
        return {
            "pattern_id":     self.pattern_id,
            "name":           self.name,
            "risk_level":     self.risk_level,
            "description":    self.description,
            "evidence":       self.evidence,
            "event_count":    len(self.matched_events),
            "detected_at":    self.detected_at,
            "sources":        sorted({e.get("source", "") for e in self.matched_events}),
        }


# ──────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────

def detect_all(
    timeline: list[dict],
    artifact_cache: dict | None = None,
) -> list[BehaviorPattern]:
    if artifact_cache is None:
        artifact_cache = {}

    patterns: list[BehaviorPattern] = []
    detectors = [
        lambda: detect_mass_file_access(timeline),
        lambda: detect_usb_then_file_create(timeline),
        lambda: detect_after_hours_activity(timeline),
        lambda: detect_cloud_storage_access(timeline),
        lambda: detect_archive_creation(timeline),
        lambda: detect_email_large_attachment(artifact_cache),
        lambda: detect_suspicious_tool_exec(timeline),
        lambda: detect_print_then_usb(timeline, artifact_cache),
        lambda: detect_recycle_before_usb(timeline),
        lambda: detect_repeated_logon_failure(timeline),
    ]

    for detector in detectors:
        try:
            result = detector()
            patterns.extend(result)
        except Exception as exc:
            logger.warning("behavior detector 오류: %s", exc)

    _RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    patterns.sort(key=lambda p: (_RISK_ORDER.get(p.risk_level, 9), p.detected_at), reverse=False)

    logger.info(
        "behavior: 총 %d 개 패턴 탐지 (critical=%d high=%d medium=%d low=%d)",
        len(patterns),
        sum(1 for p in patterns if p.risk_level == "critical"),
        sum(1 for p in patterns if p.risk_level == "high"),
        sum(1 for p in patterns if p.risk_level == "medium"),
        sum(1 for p in patterns if p.risk_level == "low"),
    )
    return patterns


# ──────────────────────────────────────────
# 탐지기 1 — 대량 파일 접근
# ──────────────────────────────────────────

def detect_mass_file_access(timeline: list[dict]) -> list[BehaviorPattern]:
    access_events = [
        e for e in timeline
        if e.get("event_type") in {"mft_accessed", "mft_modified", "mft_created"}
        and e.get("timestamp")
    ]
    if not access_events:
        return []

    access_events.sort(key=lambda e: _ts(e))
    patterns: list[BehaviorPattern] = []
    i = 0
    while i < len(access_events):
        anchor = _ts(access_events[i])
        window_events = [
            e for e in access_events[i:]
            if _ts(e) - anchor <= _MASS_ACCESS_WINDOW
        ]
        if len(window_events) >= _MASS_ACCESS_THRESHOLD:
            doc_count = sum(
                1 for e in window_events
                if _is_doc_path(e.get("description", ""))
            )
            risk = "critical" if doc_count >= 10 else "high"
            patterns.append(BehaviorPattern(
                pattern_id     = "MASS_FILE_ACCESS",
                name           = "대량 파일 접근",
                risk_level     = risk,
                description    = (
                    f"{_MASS_ACCESS_WINDOW.seconds // 60}분 내 "
                    f"{len(window_events)}개 파일 접근/수정"
                ),
                evidence       = [
                    f"시작 시각: {_fmt(anchor)}",
                    f"총 이벤트: {len(window_events)}개 "
                    f"(문서 파일 {doc_count}개 포함)",
                    f"예시: {_sample_desc(window_events, 3)}",
                ],
                matched_events = window_events,
                detected_at    = anchor,
            ))
            # 윈도우 끝 이후로 건너뜀 (중복 방지)
            i += len(window_events)
        else:
            i += 1

    return patterns


# ──────────────────────────────────────────
# 탐지기 2 — USB 연결 후 파일 대량 생성
# ──────────────────────────────────────────

def detect_usb_then_file_create(timeline: list[dict]) -> list[BehaviorPattern]:
    usb_events  = [e for e in timeline if e.get("event_type") == "usb_arrival" and e.get("timestamp")]
    file_events = [e for e in timeline if e.get("event_type") == "mft_created"  and e.get("timestamp")]
    if not usb_events or not file_events:
        return []

    patterns: list[BehaviorPattern] = []
    for usb_ev in usb_events:
        usb_ts   = _ts(usb_ev)
        created  = [
            e for e in file_events
            if timedelta(0) <= _ts(e) - usb_ts <= _USB_FILE_WINDOW
        ]
        if len(created) < _USB_FILE_THRESHOLD:
            continue

        device = (
            usb_ev.get("detail", {}).get("friendly_name")
            or usb_ev.get("description", "Unknown Device")
        )
        doc_created = [e for e in created if _is_doc_path(e.get("description", ""))]
        risk        = "critical" if doc_created else "high"

        patterns.append(BehaviorPattern(
            pattern_id     = "USB_THEN_FILE_CREATE",
            name           = "USB 연결 후 파일 대량 생성",
            risk_level     = risk,
            description    = (
                f"USB 연결({device}) 후 "
                f"{_USB_FILE_WINDOW.seconds // 60}분 내 "
                f"{len(created)}개 파일 생성"
            ),
            evidence       = [
                f"USB 연결 시각: {_fmt(usb_ts)} — {device}",
                f"생성 파일 수: {len(created)}개 (문서 {len(doc_created)}개)",
                f"예시: {_sample_desc(created, 3)}",
            ],
            matched_events = [usb_ev, *created],
            detected_at    = usb_ts,
        ))

    return patterns


# ──────────────────────────────────────────
# 탐지기 3 — 업무 외 시간 활동
# ──────────────────────────────────────────

def detect_after_hours_activity(timeline: list[dict]) -> list[BehaviorPattern]:
    after_hours = [
        e for e in timeline
        if e.get("timestamp") and _is_after_hours(_ts(e))
    ]
    if len(after_hours) < 10:
        return []

    # 날짜별로 그룹화
    by_date: dict[str, list[dict]] = defaultdict(list)
    for e in after_hours:
        date_key = _ts(e).strftime("%Y-%m-%d")
        by_date[date_key].append(e)

    patterns: list[BehaviorPattern] = []
    for date_key, events in by_date.items():
        if len(events) < 10:
            continue
        event_types = {e.get("event_type", "") for e in events}
        has_usb     = any("usb" in et for et in event_types)
        risk        = "high" if has_usb else "medium"

        patterns.append(BehaviorPattern(
            pattern_id     = "AFTER_HOURS_ACTIVITY",
            name           = "업무 외 시간 활동",
            risk_level     = risk,
            description    = (
                f"{date_key} 야간(22시~06시)에 "
                f"{len(events)}개 이벤트 발생"
            ),
            evidence       = [
                f"날짜: {date_key}",
                f"이벤트 수: {len(events)}개",
                f"포함 아티팩트: {sorted(event_types)}",
                *(["USB 활동 포함"] if has_usb else []),
            ],
            matched_events = events,
            detected_at    = _ts(min(events, key=_ts)),
        ))

    return patterns


# ──────────────────────────────────────────
# 탐지기 4 — 클라우드 스토리지 접근
# ──────────────────────────────────────────

def detect_cloud_storage_access(timeline: list[dict]) -> list[BehaviorPattern]:
    cloud_events: list[dict] = []
    for e in timeline:
        if e.get("event_type") not in {"browser_history", "browser_download"}:
            continue
        url = e.get("description", "")
        if any(domain in url for domain in _CLOUD_DOMAINS):
            cloud_events.append(e)

    if not cloud_events:
        return []

    # 도메인별 집계
    domain_counts: dict[str, int] = defaultdict(int)
    for e in cloud_events:
        url = e.get("description", "")
        for domain in _CLOUD_DOMAINS:
            if domain in url:
                domain_counts[domain] += 1
                break

    risk = "critical" if any(
        e.get("event_type") == "browser_download" for e in cloud_events
    ) else "high"

    return [BehaviorPattern(
        pattern_id     = "CLOUD_STORAGE_ACCESS",
        name           = "클라우드 스토리지 접근",
        risk_level     = risk,
        description    = f"클라우드 스토리지 {len(cloud_events)}회 접근",
        evidence       = [
            f"도메인별 접근 횟수: {dict(domain_counts)}",
            f"다운로드 포함: {'예' if risk == 'critical' else '아니오'}",
            f"예시 URL: {_sample_desc(cloud_events, 3)}",
        ],
        matched_events = cloud_events,
        detected_at    = _ts(min(cloud_events, key=_ts)),
    )]


# ──────────────────────────────────────────
# 탐지기 5 — 압축 파일 생성
# ──────────────────────────────────────────

def detect_archive_creation(timeline: list[dict]) -> list[BehaviorPattern]:
    archive_events = [
        e for e in timeline
        if e.get("event_type") == "mft_created"
        and any(
            e.get("description", "").lower().endswith(ext)
            for ext in _ARCHIVE_EXTS
        )
    ]
    if not archive_events:
        return []

    return [BehaviorPattern(
        pattern_id     = "ARCHIVE_CREATION",
        name           = "압축 파일 생성",
        risk_level     = "high",
        description    = f"압축 파일 {len(archive_events)}개 생성",
        evidence       = [
            f"생성된 압축 파일: {_sample_desc(archive_events, 5)}",
        ],
        matched_events = archive_events,
        detected_at    = _ts(min(archive_events, key=_ts)),
    )]


# ──────────────────────────────────────────
# 탐지기 6 — 이메일 대용량 첨부 발송
# ──────────────────────────────────────────

def detect_email_large_attachment(artifact_cache: dict) -> list[BehaviorPattern]:
    ost_entries = artifact_cache.get("ost_pst", [])
    if not ost_entries:
        return []

    suspicious: list[dict] = []
    for entry in ost_entries:
        if not entry.get("has_attachment"):
            continue
        # 발송 메일 (submit_time 있고 수신자 있음)
        if not entry.get("submit_time") or not entry.get("recipients_to"):
            continue
        attachments = entry.get("attachments", [])
        large = [a for a in attachments if a.get("size", 0) >= _LARGE_ATTACHMENT_SIZE]
        if large:
            suspicious.append(entry)

    if not suspicious:
        return []

    total_attachments = sum(
        len([a for a in e.get("attachments", []) if a.get("size", 0) >= _LARGE_ATTACHMENT_SIZE])
        for e in suspicious
    )

    return [BehaviorPattern(
        pattern_id     = "EMAIL_LARGE_ATTACHMENT",
        name           = "대용량 첨부 이메일 발송",
        risk_level     = "high",
        description    = (
            f"5MB 이상 첨부 발송 이메일 {len(suspicious)}건 "
            f"(첨부 파일 {total_attachments}개)"
        ),
        evidence       = [
            f"발송 건수: {len(suspicious)}건",
            f"대용량 첨부 합계: {total_attachments}개",
            f"예시 제목: {[e.get('subject','') for e in suspicious[:3]]}",
        ],
        matched_events = [
            {
                "timestamp":   e.get("submit_time"),
                "event_type":  "email_sent",
                "source":      "OST/PST",
                "description": e.get("subject", ""),
                "detail":      e,
            }
            for e in suspicious
        ],
        detected_at = min(
            (e["submit_time"] for e in suspicious if e.get("submit_time")),
            default=datetime.min.replace(tzinfo=timezone.utc),
        ),
    )]


# ──────────────────────────────────────────
# 탐지기 7 — 의심 도구 실행
# ──────────────────────────────────────────

def detect_suspicious_tool_exec(timeline: list[dict]) -> list[BehaviorPattern]:
    exec_events = [
        e for e in timeline
        if e.get("event_type") == "program_execution"
    ]
    if not exec_events:
        return []

    matched: list[dict] = []
    for e in exec_events:
        name = (e.get("description", "") or "").lower()
        if any(tool in name for tool in _SUSPICIOUS_TOOLS):
            matched.append(e)

    if not matched:
        return []

    tool_names = [e.get("description", "") for e in matched]
    return [BehaviorPattern(
        pattern_id     = "SUSPICIOUS_TOOL_EXEC",
        name           = "의심 도구 실행",
        risk_level     = "critical",
        description    = f"데이터 유출 의심 도구 {len(matched)}건 실행",
        evidence       = [
            f"실행된 도구: {tool_names[:10]}",
            f"소스: {sorted({e.get('source','') for e in matched})}",
        ],
        matched_events = matched,
        detected_at    = _ts(min(matched, key=_ts)),
    )]


# ──────────────────────────────────────────
# 탐지기 8 — 인쇄 후 USB 연결
# ──────────────────────────────────────────

def detect_print_then_usb(
    timeline: list[dict],
    artifact_cache: dict,
) -> list[BehaviorPattern]:
    spool_entries = artifact_cache.get("spool", [])
    usb_events    = [e for e in timeline if e.get("event_type") == "usb_arrival"]
    if not spool_entries or not usb_events:
        return []

    patterns: list[BehaviorPattern] = []
    for spool in spool_entries:
        spool_ts = spool.get("timestamp")
        if not isinstance(spool_ts, datetime):
            continue
        spool_ts = _to_utc(spool_ts)

        nearby_usb = [
            e for e in usb_events
            if timedelta(0) <= _ts(e) - spool_ts <= _PRINT_USB_WINDOW
        ]
        if not nearby_usb:
            continue

        doc_name    = spool.get("document_name", "")
        is_sensitive = any(kw in doc_name.lower() for kw in _SENSITIVE_KEYWORDS)
        risk         = "critical" if is_sensitive else "medium"

        patterns.append(BehaviorPattern(
            pattern_id     = "PRINT_THEN_USB",
            name           = "인쇄 후 USB 연결",
            risk_level     = risk,
            description    = (
                f"문서 인쇄 후 {_PRINT_USB_WINDOW.seconds // 60}분 내 USB 연결"
            ),
            evidence       = [
                f"인쇄 문서: {doc_name} ({_fmt(spool_ts)})",
                f"USB 연결: {len(nearby_usb)}건",
                *(["⚠ 민감 키워드 포함 문서명"] if is_sensitive else []),
            ],
            matched_events = [
                {
                    "timestamp":   spool_ts,
                    "event_type":  "print_job",
                    "source":      "Spool",
                    "description": doc_name,
                    "detail":      spool,
                },
                *nearby_usb,
            ],
            detected_at = spool_ts,
        ))

    return patterns


# ──────────────────────────────────────────
# 탐지기 9 — USB 연결 전 대량 파일 삭제
# ──────────────────────────────────────────

def detect_recycle_before_usb(timeline: list[dict]) -> list[BehaviorPattern]:
    usb_events = [e for e in timeline if e.get("event_type") == "usb_arrival"]
    recycle_events = [
        e for e in timeline
        if e.get("event_type") in {"mft_created", "mft_modified"}
        and "recycle.bin" in e.get("description", "").lower()
    ]
    if not usb_events or not recycle_events:
        return []

    window  = timedelta(hours=1)
    patterns: list[BehaviorPattern] = []

    for usb_ev in usb_events:
        usb_ts = _ts(usb_ev)
        before = [
            e for e in recycle_events
            if timedelta(0) <= usb_ts - _ts(e) <= window
        ]
        if len(before) < 5:
            continue

        patterns.append(BehaviorPattern(
            pattern_id     = "RECYCLE_BEFORE_USB",
            name           = "USB 연결 전 파일 삭제",
            risk_level     = "critical",
            description    = (
                f"USB 연결 1시간 전 {len(before)}개 파일 휴지통 이동 "
                f"(증거 인멸 의심)"
            ),
            evidence       = [
                f"USB 연결 시각: {_fmt(usb_ts)}",
                f"삭제된 파일 수: {len(before)}개",
                f"예시: {_sample_desc(before, 3)}",
            ],
            matched_events = [*before, usb_ev],
            detected_at    = _ts(min(before, key=_ts)),
        ))

    return patterns


# ──────────────────────────────────────────
# 탐지기 10 — 반복 로그인 실패
# ──────────────────────────────────────────

def detect_repeated_logon_failure(timeline: list[dict]) -> list[BehaviorPattern]:
    fail_events = [
        e for e in timeline
        if e.get("event_type") == "eventlog_timestamp"
        and "4625" in str(e.get("detail", {}).get("event_id", ""))
        and e.get("timestamp")
    ]
    if not fail_events:
        return []

    fail_events.sort(key=_ts)
    patterns: list[BehaviorPattern] = []
    i = 0
    while i < len(fail_events):
        anchor       = _ts(fail_events[i])
        window_group = [
            e for e in fail_events[i:]
            if _ts(e) - anchor <= _LOGON_FAIL_WINDOW
        ]
        if len(window_group) >= _LOGON_FAIL_THRESHOLD:
            patterns.append(BehaviorPattern(
                pattern_id     = "REPEATED_LOGON_FAILURE",
                name           = "반복 로그인 실패",
                risk_level     = "high",
                description    = (
                    f"{_LOGON_FAIL_WINDOW.seconds // 60}분 내 "
                    f"로그인 실패 {len(window_group)}회"
                ),
                evidence       = [
                    f"시작 시각: {_fmt(anchor)}",
                    f"실패 횟수: {len(window_group)}회",
                ],
                matched_events = window_group,
                detected_at    = anchor,
            ))
            i += len(window_group)
        else:
            i += 1

    return patterns


# ──────────────────────────────────────────
# 내부 유틸
# ──────────────────────────────────────────

def _to_utc(ts) -> datetime:
    if not isinstance(ts, datetime):
        return datetime.min.replace(tzinfo=timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _ts(event: dict) -> datetime:
    return _to_utc(event.get("timestamp"))


def _fmt(dt: datetime) -> str:
    if not isinstance(dt, datetime):
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _is_after_hours(dt: datetime) -> bool:
    hour = dt.hour
    return hour >= _AFTER_HOURS_START or hour < _AFTER_HOURS_END


def _is_doc_path(path: str) -> bool:
    doc_exts = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".hwp", ".hwpx", ".txt", ".csv",
    }
    lower = path.lower()
    return any(lower.endswith(ext) for ext in doc_exts)


def _sample_desc(events: list[dict], n: int) -> list[str]:
    return [
        e.get("description", "")
        for e in events[:n]
        if e.get("description")
    ]