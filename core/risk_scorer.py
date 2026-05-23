from __future__ import annotations

import math
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional

from .risk_report import (
    DetectedPattern,
    NarrativeBuilder,
    RiskReport,
    ScoreBreakdown,
    TriggeredCombo,
)
from .risk_rules import (
    COMBINATION_RULES,
    FREQUENCY_MAX_MULTIPLIER,
    PATTERN_SCORES,
    TIME_DECAY_CONFIG,
    CombinationRule,
    RiskLevel,
    get_frequency_multiplier,
    score_to_level,
)


# ──────────────────────────────────────────────
# 입력 이벤트 스펙
# ──────────────────────────────────────────────

class RiskEvent:

    __slots__ = ("pattern_id", "occurred_at", "metadata")

    def __init__(
        self,
        pattern_id: str,
        occurred_at: datetime,
        metadata: Optional[dict] = None,
    ) -> None:
        self.pattern_id  = pattern_id
        self.occurred_at = occurred_at
        self.metadata    = metadata or {}

    def __repr__(self) -> str:
        return (
            f"RiskEvent(pattern_id={self.pattern_id!r}, "
            f"occurred_at={self.occurred_at.isoformat()})"
        )


# ──────────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────────

def _time_decay_factor(event_time: datetime, now: datetime) -> float:
    cfg = TIME_DECAY_CONFIG
    age_hours = (now - event_time).total_seconds() / 3600

    # 최대 보존 기간 초과 → 0
    if age_hours > cfg.max_age_hours:
        return 0.0

    # 지수 감쇠
    factor = 0.5 ** (age_hours / cfg.half_life_hours)
    return max(cfg.min_retention, factor)


def _check_ordered(
    pattern_ids: List[str],
    events_by_pattern: Dict[str, List[RiskEvent]],
) -> bool:
    times: list[datetime] = []
    for pid in pattern_ids:
        evts = events_by_pattern.get(pid)
        if not evts:
            return False
        times.append(max(e.occurred_at for e in evts))

    return all(times[i] <= times[i + 1] for i in range(len(times) - 1))


def _combo_time_span(
    pattern_ids: List[str],
    events_by_pattern: Dict[str, List[RiskEvent]],
) -> float:
    all_times: list[datetime] = []
    for pid in pattern_ids:
        for e in events_by_pattern.get(pid, []):
            all_times.append(e.occurred_at)

    if not all_times:
        return 0.0
    return (max(all_times) - min(all_times)).total_seconds()


def _latest_event_time(
    pattern_ids: List[str],
    events_by_pattern: Dict[str, List[RiskEvent]],
) -> datetime:
    all_times: list[datetime] = []
    for pid in pattern_ids:
        for e in events_by_pattern.get(pid, []):
            all_times.append(e.occurred_at)
    return max(all_times) if all_times else datetime.utcnow()


# ──────────────────────────────────────────────
# 핵심 평가 엔진
# ──────────────────────────────────────────────

class RiskScorer:
    @staticmethod
    def evaluate(
        events: Iterable[RiskEvent],
        subject_id: str,
        evaluation_window_hours: float = 24.0,
        now: Optional[datetime] = None,
        generate_narrative: bool = True,
    ) -> RiskReport:
        now = now or datetime.now(tz=timezone.utc)
        cutoff = now - timedelta(hours=evaluation_window_hours)

        # ── 1. 이벤트 필터링 및 패턴별 그룹화 ──────
        events_by_pattern: Dict[str, List[RiskEvent]] = defaultdict(list)

        for evt in events:
            # 알 수 없는 패턴은 무시
            if evt.pattern_id not in PATTERN_SCORES:
                continue
            # 평가 창 밖 이벤트 제외
            if evt.occurred_at < cutoff:
                continue
            # 시간 감쇠 0인 이벤트 제외 (max_age_hours 초과)
            if _time_decay_factor(evt.occurred_at, now) == 0.0:
                continue
            events_by_pattern[evt.pattern_id].append(evt)

        # ── 2. 단일 패턴 점수 계산 ──────────────────
        detected_patterns: List[DetectedPattern] = []
        adjusted_total = 0.0
        base_total = 0.0

        for pid, evts in events_by_pattern.items():
            rule: PatternRule = PATTERN_SCORES[pid]
            count = len(evts)

            # 가장 최근 이벤트의 시간 감쇠 계수 사용
            latest = max(evts, key=lambda e: e.occurred_at)
            earliest = min(evts, key=lambda e: e.occurred_at)
            decay = _time_decay_factor(latest.occurred_at, now)

            # 빈도 가중치
            freq_mult = get_frequency_multiplier(count)

            # 유효 점수 = 기본 점수 × 감쇠 × 빈도
            effective = rule.base_score * decay * freq_mult

            base_total += rule.base_score
            adjusted_total += effective

            detected_patterns.append(DetectedPattern(
                pattern_id           = pid,
                display_name         = rule.display_name,
                base_score           = rule.base_score,
                effective_score      = effective,
                occurrence_count     = count,
                first_seen           = earliest.occurred_at,
                last_seen            = latest.occurred_at,
                frequency_multiplier = freq_mult,
                time_decay_factor    = decay,
                category             = rule.category.value,
                mitre_technique      = rule.mitre_technique,
            ))

        # ── 3. 조합 규칙 매칭 ───────────────────────
        triggered_combos: List[TriggeredCombo] = []
        combo_bonus_total = 0.0

        for combo in COMBINATION_RULES:
            matched = _match_combination(combo, events_by_pattern, now)
            if matched:
                triggered_combos.append(matched)
                combo_bonus_total += matched.bonus_score

        # ── 4. 최종 점수 산출 ───────────────────────
        raw_total   = adjusted_total + combo_bonus_total
        final_score = min(100.0, max(0.0, raw_total))
        risk_level  = score_to_level(final_score)

        breakdown = ScoreBreakdown(
            base_pattern_score    = base_total,
            adjusted_pattern_score= adjusted_total,
            combo_bonus_score     = combo_bonus_total,
            raw_total             = raw_total,
            final_score           = final_score,
            pattern_count         = len(detected_patterns),
            combo_count           = len(triggered_combos),
        )

        # ── 5. 리포트 조립 ──────────────────────────
        report = RiskReport(
            report_id               = str(uuid.uuid4()),
            subject_id              = subject_id,
            evaluated_at            = now,
            evaluation_window_hours = evaluation_window_hours,
            risk_level              = risk_level,
            score                   = final_score,
            breakdown               = breakdown,
            detected_patterns       = detected_patterns,
            triggered_combos        = triggered_combos,
        )

        if generate_narrative:
            NarrativeBuilder.build(report)

        return report

    @staticmethod
    def evaluate_batch(
        user_events_map: Dict[str, Iterable[RiskEvent]],
        evaluation_window_hours: float = 24.0,
        now: Optional[datetime] = None,
        generate_narrative: bool = True,
    ) -> Dict[str, RiskReport]:
        return {
            uid: RiskScorer.evaluate(
                events                  = evts,
                subject_id              = uid,
                evaluation_window_hours = evaluation_window_hours,
                now                     = now,
                generate_narrative      = generate_narrative,
            )
            for uid, evts in user_events_map.items()
        }

    @staticmethod
    def top_risk_users(
        reports: Dict[str, RiskReport],
        min_level: RiskLevel = RiskLevel.MEDIUM,
        limit: int = 10,
    ) -> List[RiskReport]:
        level_order = {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH    : 3,
            RiskLevel.MEDIUM  : 2,
            RiskLevel.LOW     : 1,
            RiskLevel.NONE    : 0,
        }
        threshold = level_order[min_level]

        filtered = [
            r for r in reports.values()
            if level_order[r.risk_level] >= threshold
        ]
        return sorted(filtered, key=lambda r: r.score, reverse=True)[:limit]


# ──────────────────────────────────────────────
# 조합 매칭 로직 (모듈 내부)
# ──────────────────────────────────────────────

def _match_combination(
    combo: CombinationRule,
    events_by_pattern: Dict[str, List[RiskEvent]],
    now: datetime,
) -> Optional[TriggeredCombo]:
    required = combo.required_count if combo.required_count else len(combo.patterns)

    # 존재하는 패턴만 추림
    present_patterns = [
        pid for pid in combo.patterns
        if events_by_pattern.get(pid)
    ]

    if len(present_patterns) < required:
        return None

    # 시간 윈도우 검사: 가장 최근 이벤트 ~ 가장 오래된 이벤트 간격
    span = _combo_time_span(present_patterns, events_by_pattern)
    if span > combo.time_window_seconds:
        return None

    # 순서 검사 (ordered=True이고 required_count == 전체 패턴 수일 때만 엄격 검사)
    if combo.ordered and required == len(combo.patterns):
        if not _check_ordered(combo.patterns, events_by_pattern):
            return None

    triggered_at = _latest_event_time(present_patterns, events_by_pattern)

    return TriggeredCombo(
        rule             = combo,
        matched_patterns = present_patterns,
        time_span_seconds= span,
        bonus_score      = combo.bonus_score,
        triggered_at     = triggered_at,
    )