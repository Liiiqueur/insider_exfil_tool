from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from .risk_rules import (
    CombinationRule,
    PatternRule,
    RiskLevel,
    score_to_level,
)


# ──────────────────────────────────────────────
# 데이터 클래스
# ──────────────────────────────────────────────

@dataclass
class DetectedPattern:
    pattern_id: str                         # 패턴 식별자
    display_name: str                       # 패턴 이름
    base_score: int                         # 원래 기본 점수
    effective_score: float                  # 시간 감쇠·빈도 적용 후 점수
    occurrence_count: int                   # 평가 기간 내 발생 횟수
    first_seen: datetime                    # 최초 발생 시각
    last_seen: datetime                     # 최근 발생 시각
    frequency_multiplier: float             # 빈도 가중치
    time_decay_factor: float                # 시간 감쇠 계수 (0.0 ~ 1.0)
    category: str                           # 패턴 카테고리
    mitre_technique: Optional[str] = None  # MITRE ATT&CK ID

    @property
    def age_hours(self) -> float:
        return (datetime.utcnow() - self.last_seen).total_seconds() / 3600

    def to_dict(self) -> dict:
        return {
            "pattern_id"          : self.pattern_id,
            "display_name"        : self.display_name,
            "base_score"          : self.base_score,
            "effective_score"     : round(self.effective_score, 2),
            "occurrence_count"    : self.occurrence_count,
            "first_seen"          : self.first_seen.isoformat(),
            "last_seen"           : self.last_seen.isoformat(),
            "frequency_multiplier": round(self.frequency_multiplier, 2),
            "time_decay_factor"   : round(self.time_decay_factor, 3),
            "category"            : self.category,
            "mitre_technique"     : self.mitre_technique,
        }


@dataclass
class TriggeredCombo:
    rule: CombinationRule               # 발동된 조합 규칙
    matched_patterns: List[str]         # 실제 매칭된 패턴 ID 목록
    time_span_seconds: float            # 최초~최후 이벤트 간 시간 간격 (초)
    bonus_score: int                    # 적용된 보너스 점수
    triggered_at: datetime              # 조합이 성립된 시각 (마지막 패턴 기준)

    @property
    def time_span_str(self) -> str:
        m, s = divmod(int(self.time_span_seconds), 60)
        h, m = divmod(m, 60)
        if h:
            return f"{h}시간 {m}분"
        elif m:
            return f"{m}분 {s}초"
        return f"{s}초"

    def to_dict(self) -> dict:
        return {
            "rule_id"         : self.rule.rule_id,
            "name"            : self.rule.name,
            "matched_patterns": self.matched_patterns,
            "time_span"       : self.time_span_str,
            "bonus_score"     : self.bonus_score,
            "triggered_at"    : self.triggered_at.isoformat(),
            "severity"        : self.rule.severity.value,
        }


@dataclass
class ScoreBreakdown:
    base_pattern_score: float       # 단일 패턴 점수 합계 (감쇠·빈도 전)
    adjusted_pattern_score: float   # 감쇠·빈도 적용 후 패턴 점수
    combo_bonus_score: float        # 조합 보너스 합계
    raw_total: float                # 캡핑 전 합계
    final_score: float              # 캡핑(0~100) 후 최종 점수
    pattern_count: int              # 탐지된 패턴 수
    combo_count: int                # 발동된 조합 수

    def to_dict(self) -> dict:
        return {
            "base_pattern_score"    : round(self.base_pattern_score, 2),
            "adjusted_pattern_score": round(self.adjusted_pattern_score, 2),
            "combo_bonus_score"     : round(self.combo_bonus_score, 2),
            "raw_total"             : round(self.raw_total, 2),
            "final_score"           : round(self.final_score, 2),
            "pattern_count"         : self.pattern_count,
            "combo_count"           : self.combo_count,
        }


@dataclass
class RiskReport:
    # 식별 정보
    report_id: str                              # 리포트 고유 ID
    subject_id: str                             # 평가 대상 (사용자/세션 ID)
    evaluated_at: datetime                      # 평가 수행 시각
    evaluation_window_hours: float              # 평가 시간 창 (시간 단위)

    # 핵심 결과
    risk_level: RiskLevel                       # 위험 등급
    score: float                                # 최종 점수 (0~100)
    breakdown: ScoreBreakdown                   # 점수 분해 내역

    # 탐지 내역
    detected_patterns: List[DetectedPattern]    # 탐지된 단일 패턴 목록
    triggered_combos: List[TriggeredCombo]      # 발동된 조합 목록

    # 내러티브 (NarrativeBuilder가 채워줌)
    summary: str = ""                           # 1~2문장 요약
    narrative: str = ""                         # 상세 설명
    recommendations: List[str] = field(default_factory=list)   # 권고 조치

    @property
    def is_alert_required(self) -> bool:
        return self.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)

    @property
    def top_patterns(self) -> List[DetectedPattern]:
        return sorted(
            self.detected_patterns,
            key=lambda p: p.effective_score,
            reverse=True,
        )[:5]

    def to_dict(self) -> dict:
        return {
            "report_id"               : self.report_id,
            "subject_id"              : self.subject_id,
            "evaluated_at"            : self.evaluated_at.isoformat(),
            "evaluation_window_hours" : self.evaluation_window_hours,
            "risk_level"              : self.risk_level.value,
            "score"                   : round(self.score, 2),
            "breakdown"               : self.breakdown.to_dict(),
            "detected_patterns"       : [p.to_dict() for p in self.detected_patterns],
            "triggered_combos"        : [c.to_dict() for c in self.triggered_combos],
            "summary"                 : self.summary,
            "narrative"               : self.narrative,
            "recommendations"         : self.recommendations,
            "is_alert_required"       : self.is_alert_required,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


# ──────────────────────────────────────────────
# 내러티브 생성기
# ──────────────────────────────────────────────

class NarrativeBuilder:
    # 위험 등급별 헤드라인
    _LEVEL_HEADLINE: dict[RiskLevel, str] = {
        RiskLevel.CRITICAL: "🔴 즉각 대응 필요 — 내부자 위협 고위험 징후가 감지되었습니다.",
        RiskLevel.HIGH    : "🟠 높은 위험 — 복수의 이상 행위가 단시간에 집중되었습니다.",
        RiskLevel.MEDIUM  : "🟡 중간 위험 — 주의가 필요한 행동 패턴이 발견되었습니다.",
        RiskLevel.LOW     : "🟢 낮은 위험 — 경미한 이상 징후가 관찰되었습니다.",
        RiskLevel.NONE    : "⚪ 위험 없음 — 특이 사항이 탐지되지 않았습니다.",
    }

    # 카테고리별 설명 접두어
    _CATEGORY_PREFIX: dict[str, str] = {
        "data_exfiltration": "데이터 유출 관련",
        "device_usage"     : "외부 장치",
        "access_anomaly"   : "비정상 접근",
        "credential_abuse" : "자격 증명 남용",
        "communication"    : "비정상 통신",
        "policy_violation" : "정책 위반",
        "reconnaissance"   : "사전 정찰",
    }

    # 패턴 카테고리별 권고사항
    _CATEGORY_RECOMMENDATIONS: dict[str, list[str]] = {
        "data_exfiltration": [
            "해당 사용자의 파일 접근 로그 전수 감사",
            "DLP(Data Loss Prevention) 규칙 강화 및 즉시 알림 설정",
            "유출 대상 파일의 민감도 분류 재검토",
        ],
        "device_usage": [
            "USB 장치 목록 및 기록된 파일 내용 조회",
            "미인가 장치 차단 정책 적용 검토",
            "해당 세션 전후 물리 보안 CCTV 영상 확인",
        ],
        "access_anomaly": [
            "접근 시간대·위치 이상 여부 HR 부서와 교차 확인",
            "VPN/SSO 로그 상세 분석",
            "해당 계정 임시 접근 제한 및 재인증 요구",
        ],
        "credential_abuse": [
            "계정 비밀번호 즉시 재설정 및 MFA 강제 적용",
            "권한 상승 시도 대상 리소스 접근 감사",
            "동일 자격 증명으로 접근한 다른 시스템 확인",
        ],
        "communication": [
            "연결된 외부 IP/도메인의 위협 인텔리전스 조회",
            "네트워크 트래픽 캡처 및 내용 분석",
            "방화벽 정책에 해당 목적지 차단 규칙 추가",
        ],
        "reconnaissance": [
            "화면 캡처·녹화 도구 설치 경로 포렌식 조사",
            "임시 디렉토리 내 파일 목록 즉시 보존",
            "해당 사용자 접근 가능한 민감 데이터 범위 파악",
        ],
        "policy_violation": [
            "HR 부서에 해당 사용자 상태 즉시 확인",
            "보안 솔루션 비활성화 시도 관련 감사 증거 보존",
            "법무 및 컴플라이언스 팀 즉시 통보",
        ],
    }

    # 위험 등급별 공통 권고사항
    _LEVEL_RECOMMENDATIONS: dict[RiskLevel, list[str]] = {
        RiskLevel.CRITICAL: [
            "즉시 보안팀 에스컬레이션 및 인시던트 응답 절차 개시",
            "해당 사용자 계정 일시 정지 후 관리자 검토",
            "법적 증거 보전을 위한 포렌식 이미징 수행",
        ],
        RiskLevel.HIGH: [
            "24시간 내 보안 담당자 검토 및 확인 조사 실시",
            "해당 사용자 활동 모니터링 강도 상향",
            "사용자 본인 인터뷰를 통한 정황 파악",
        ],
        RiskLevel.MEDIUM: [
            "72시간 내 담당 팀장 및 보안팀 검토",
            "해당 패턴이 반복될 경우 자동 알림 설정",
        ],
        RiskLevel.LOW: [
            "정기 보안 검토 시 포함하여 재평가",
        ],
        RiskLevel.NONE: [],
    }

    @classmethod
    def build(cls, report: RiskReport) -> RiskReport:
        report.summary         = cls._build_summary(report)
        report.narrative       = cls._build_narrative(report)
        report.recommendations = cls._build_recommendations(report)
        return report

    # ── 내부 메서드 ───────────────────────────

    @classmethod
    def _build_summary(cls, report: RiskReport) -> str:
        headline = cls._LEVEL_HEADLINE[report.risk_level]

        if report.risk_level == RiskLevel.NONE:
            return headline

        parts = [headline]

        # 가장 높은 점수 패턴 언급
        if report.top_patterns:
            top = report.top_patterns[0]
            parts.append(
                f"주요 원인: '{top.display_name}' "
                f"(점수 기여 {top.effective_score:.1f}점, {top.occurrence_count}회 발생)."
            )

        # 조합 발동 여부
        if report.triggered_combos:
            combo_names = ", ".join(c.rule.name for c in report.triggered_combos[:2])
            parts.append(f"행위 조합 [{combo_names}] 이(가) 성립하여 위험도가 상승했습니다.")

        return " ".join(parts)

    @classmethod
    def _build_narrative(cls, report: RiskReport) -> str:
        sections: list[str] = []

        # 1. 평가 개요
        window_str = (
            f"{int(report.evaluation_window_hours)}시간"
            if report.evaluation_window_hours >= 1
            else f"{int(report.evaluation_window_hours * 60)}분"
        )
        sections.append(
            f"■ 평가 개요\n"
            f"대상: {report.subject_id} | "
            f"평가 시각: {report.evaluated_at.strftime('%Y-%m-%d %H:%M UTC')} | "
            f"분석 기간: 최근 {window_str}\n"
            f"최종 위험 점수: {report.score:.1f}/100 ({report.risk_level.value})"
        )

        # 2. 탐지된 패턴별 설명
        if report.detected_patterns:
            pattern_lines = ["■ 탐지된 이상 행위"]
            for dp in report.top_patterns:
                prefix = cls._CATEGORY_PREFIX.get(dp.category, dp.category)
                decay_pct = int(dp.time_decay_factor * 100)
                freq_info = (
                    f"{dp.occurrence_count}회 발생"
                    if dp.occurrence_count > 1
                    else "1회 발생"
                )
                mitre_str = f" [MITRE {dp.mitre_technique}]" if dp.mitre_technique else ""
                pattern_lines.append(
                    f"  • [{prefix}] {dp.display_name}{mitre_str}\n"
                    f"    → 기여 점수: {dp.effective_score:.1f}점 | "
                    f"{freq_info} | "
                    f"시간 감쇠: {decay_pct}% 적용 | "
                    f"마지막 발생: {dp.last_seen.strftime('%Y-%m-%d %H:%M')}"
                )
            sections.append("\n".join(pattern_lines))

        # 3. 조합 규칙 설명
        if report.triggered_combos:
            combo_lines = ["■ 행위 조합 분석"]
            for tc in report.triggered_combos:
                combo_lines.append(
                    f"  • [{tc.rule.rule_id}] {tc.rule.name}\n"
                    f"    → 조합 보너스: +{tc.bonus_score}점 | "
                    f"발생 구간: {tc.time_span_str}\n"
                    f"    → {tc.rule.narrative_template}"
                )
            sections.append("\n".join(combo_lines))

        # 4. 점수 분해
        bd = report.breakdown
        sections.append(
            f"■ 점수 산출 내역\n"
            f"  단일 패턴 합계(조정 후): {bd.adjusted_pattern_score:.1f}점\n"
            f"  조합 보너스 합계:         {bd.combo_bonus_score:.1f}점\n"
            f"  합산(캡핑 전):            {bd.raw_total:.1f}점\n"
            f"  최종 점수(0~100):         {bd.final_score:.1f}점"
        )

        return "\n\n".join(sections)

    @classmethod
    def _build_recommendations(cls, report: RiskReport) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []

        def _add(items: list[str]) -> None:
            for item in items:
                if item not in seen:
                    seen.add(item)
                    result.append(item)

        # 위험 등급별 공통 권고
        _add(cls._LEVEL_RECOMMENDATIONS.get(report.risk_level, []))

        # 발동된 조합의 카테고리 권고
        for tc in report.triggered_combos:
            for pid in tc.matched_patterns:
                from .risk_rules import PATTERN_SCORES
                rule = PATTERN_SCORES.get(pid)
                if rule:
                    _add(cls._CATEGORY_RECOMMENDATIONS.get(rule.category.value, []))

        # 탐지된 패턴의 카테고리 권고
        for dp in report.top_patterns:
            _add(cls._CATEGORY_RECOMMENDATIONS.get(dp.category, []))

        return result