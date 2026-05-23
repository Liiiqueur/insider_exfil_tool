from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


# ──────────────────────────────────────────────
# 열거형 정의
# ──────────────────────────────────────────────

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"   # 90+
    HIGH     = "HIGH"       # 70–89
    MEDIUM   = "MEDIUM"     # 40–69
    LOW      = "LOW"        # 10–39
    NONE     = "NONE"       # 0–9


class PatternCategory(str, Enum):
    DATA_EXFILTRATION  = "data_exfiltration"   # 데이터 유출 시도
    DEVICE_USAGE       = "device_usage"        # 외부 장치 사용
    ACCESS_ANOMALY     = "access_anomaly"      # 비정상 접근
    CREDENTIAL_ABUSE   = "credential_abuse"    # 자격 증명 오용
    COMMUNICATION      = "communication"       # 비정상 통신
    POLICY_VIOLATION   = "policy_violation"    # 정책 위반
    RECONNAISSANCE     = "reconnaissance"      # 정찰 행위


# ──────────────────────────────────────────────
# 단일 패턴 점수 규칙
# ──────────────────────────────────────────────

@dataclass(frozen=True)
class PatternRule:
    pattern_id: str             # 고유 패턴 식별자
    display_name: str           # 사람이 읽을 수 있는 이름
    category: PatternCategory   # 카테고리
    base_score: int             # 기본 위험 점수 (0–100)
    description: str            # 위험 설명
    mitre_technique: Optional[str] = None   # MITRE ATT&CK 기법 ID
    requires_context: bool = False          # 맥락 없이 단독 평가 가능 여부


PATTERN_SCORES: dict[str, PatternRule] = {
    # ── 데이터 유출 ──────────────────────────────
    "large_file_copy": PatternRule(
        pattern_id    = "large_file_copy",
        display_name  = "대용량 파일 복사",
        category      = PatternCategory.DATA_EXFILTRATION,
        base_score    = 35,
        description   = "단시간 내 대용량 파일(≥100MB) 복사 감지",
        mitre_technique = "T1020",
    ),
    "sensitive_file_access": PatternRule(
        pattern_id    = "sensitive_file_access",
        display_name  = "민감 파일 접근",
        category      = PatternCategory.DATA_EXFILTRATION,
        base_score    = 40,
        description   = "기밀/개인정보 분류 파일 다수 접근",
        mitre_technique = "T1083",
    ),
    "bulk_file_download": PatternRule(
        pattern_id    = "bulk_file_download",
        display_name  = "대량 파일 다운로드",
        category      = PatternCategory.DATA_EXFILTRATION,
        base_score    = 45,
        description   = "짧은 시간 내 다수 파일을 로컬로 다운로드",
        mitre_technique = "T1530",
    ),
    "cloud_upload_unusual": PatternRule(
        pattern_id    = "cloud_upload_unusual",
        display_name  = "비정상 클라우드 업로드",
        category      = PatternCategory.DATA_EXFILTRATION,
        base_score    = 50,
        description   = "비인가 클라우드 스토리지로의 업로드 감지",
        mitre_technique = "T1567",
    ),
    "email_attachment_large": PatternRule(
        pattern_id    = "email_attachment_large",
        display_name  = "대용량 이메일 첨부",
        category      = PatternCategory.DATA_EXFILTRATION,
        base_score    = 30,
        description   = "외부 수신자에게 대용량 첨부파일 이메일 발송",
        mitre_technique = "T1048",
    ),

    # ── 외부 장치 ──────────────────────────────
    "usb_connected": PatternRule(
        pattern_id    = "usb_connected",
        display_name  = "USB 장치 연결",
        category      = PatternCategory.DEVICE_USAGE,
        base_score    = 25,
        description   = "USB 저장 장치 연결 감지",
        mitre_technique = "T1091",
    ),
    "usb_write": PatternRule(
        pattern_id    = "usb_write",
        display_name  = "USB 쓰기",
        category      = PatternCategory.DEVICE_USAGE,
        base_score    = 45,
        description   = "USB 장치에 데이터 기록",
        mitre_technique = "T1091",
    ),
    "unauthorized_device": PatternRule(
        pattern_id    = "unauthorized_device",
        display_name  = "비인가 장치 연결",
        category      = PatternCategory.DEVICE_USAGE,
        base_score    = 55,
        description   = "허용 목록에 없는 외부 장치 연결",
        mitre_technique = "T1200",
    ),

    # ── 비정상 접근 ────────────────────────────
    "after_hours_access": PatternRule(
        pattern_id    = "after_hours_access",
        display_name  = "비업무 시간 접근",
        category      = PatternCategory.ACCESS_ANOMALY,
        base_score    = 20,
        description   = "야간/주말 등 비업무 시간 시스템 접근",
        mitre_technique = "T1078",
    ),
    "privilege_escalation": PatternRule(
        pattern_id    = "privilege_escalation",
        display_name  = "권한 상승 시도",
        category      = PatternCategory.CREDENTIAL_ABUSE,
        base_score    = 60,
        description   = "정상 권한 이상의 자원 접근 시도",
        mitre_technique = "T1068",
    ),
    "multiple_failed_login": PatternRule(
        pattern_id    = "multiple_failed_login",
        display_name  = "반복 로그인 실패",
        category      = PatternCategory.CREDENTIAL_ABUSE,
        base_score    = 30,
        description   = "단시간 내 다수의 인증 실패",
        mitre_technique = "T1110",
    ),
    "vpn_from_new_location": PatternRule(
        pattern_id    = "vpn_from_new_location",
        display_name  = "신규 위치 VPN 접속",
        category      = PatternCategory.ACCESS_ANOMALY,
        base_score    = 25,
        description   = "이전에 없던 지역/IP에서 VPN 접속",
        mitre_technique = "T1078",
    ),
    "admin_tool_usage": PatternRule(
        pattern_id    = "admin_tool_usage",
        display_name  = "관리자 도구 비정상 사용",
        category      = PatternCategory.ACCESS_ANOMALY,
        base_score    = 35,
        description   = "PsExec, WMI 등 관리 도구를 비정상적으로 실행",
        mitre_technique = "T1569",
    ),

    # ── 비정상 통신 ────────────────────────────
    "suspicious_network_conn": PatternRule(
        pattern_id    = "suspicious_network_conn",
        display_name  = "의심 네트워크 연결",
        category      = PatternCategory.COMMUNICATION,
        base_score    = 40,
        description   = "블랙리스트 IP/도메인 또는 비정상 포트로의 연결",
        mitre_technique = "T1071",
    ),
    "data_staging": PatternRule(
        pattern_id    = "data_staging",
        display_name  = "데이터 스테이징",
        category      = PatternCategory.RECONNAISSANCE,
        base_score    = 45,
        description   = "임시 디렉토리에 파일을 모아두는 행위",
        mitre_technique = "T1074",
    ),
    "screen_capture": PatternRule(
        pattern_id    = "screen_capture",
        display_name  = "화면 캡처",
        category      = PatternCategory.RECONNAISSANCE,
        base_score    = 30,
        description   = "반복적인 화면 캡처 또는 녹화 도구 실행",
        mitre_technique = "T1113",
    ),
    "policy_bypass_attempt": PatternRule(
        pattern_id    = "policy_bypass_attempt",
        display_name  = "정책 우회 시도",
        category      = PatternCategory.POLICY_VIOLATION,
        base_score    = 50,
        description   = "DLP·방화벽·보안 소프트웨어 비활성화 또는 우회",
        mitre_technique = "T1562",
    ),
    "resignation_flag": PatternRule(
        pattern_id    = "resignation_flag",
        display_name  = "퇴직 예정 플래그",
        category      = PatternCategory.POLICY_VIOLATION,
        base_score    = 15,
        description   = "HR 시스템에 퇴직 처리된 사용자의 접근",
        requires_context = True,
    ),
}


# ──────────────────────────────────────────────
# 행위 조합 규칙
# ──────────────────────────────────────────────

@dataclass(frozen=True)
class CombinationRule:
    rule_id: str                    # 조합 규칙 고유 ID
    name: str                       # 조합 이름
    patterns: List[str]             # 구성 패턴 ID 목록 (순서 무관)
    ordered: bool                   # True = 패턴이 시간 순서대로 발생해야 함
    time_window_seconds: int        # 조합이 성립하는 최대 시간 간격 (초)
    bonus_score: int                # 조합 성립 시 추가 점수
    severity: RiskLevel             # 조합이 발동할 때의 최소 위험 등급
    narrative_template: str         # 리포트 내러티브 템플릿
    required_count: int = 2         # 패턴 중 몇 개가 발생해야 조합 성립 (기본 전체)


COMBINATION_RULES: List[CombinationRule] = [

    # ── Tier 1: 고위험 조합 (CRITICAL) ──────────

    CombinationRule(
        rule_id             = "C001",
        name                = "파일 접근 후 USB 반출",
        patterns            = ["sensitive_file_access", "usb_connected", "usb_write"],
        ordered             = True,
        time_window_seconds = 1800,     # 30분
        bonus_score         = 55,
        severity            = RiskLevel.CRITICAL,
        narrative_template  = (
            "민감 파일 접근 이후 USB 장치를 연결하여 데이터를 기록했습니다. "
            "내부 자료 물리적 반출 시도 패턴에 해당합니다."
        ),
    ),

    CombinationRule(
        rule_id             = "C002",
        name                = "대량 다운로드 → 클라우드 업로드",
        patterns            = ["bulk_file_download", "cloud_upload_unusual"],
        ordered             = True,
        time_window_seconds = 3600,     # 1시간
        bonus_score         = 60,
        severity            = RiskLevel.CRITICAL,
        narrative_template  = (
            "대량 파일을 로컬로 다운로드한 직후 비인가 클라우드 스토리지에 업로드했습니다. "
            "데이터 외부 유출 전형적 2단계 패턴입니다."
        ),
    ),

    CombinationRule(
        rule_id             = "C003",
        name                = "퇴직 예정자 데이터 집중 접근",
        patterns            = ["resignation_flag", "bulk_file_download", "large_file_copy"],
        ordered             = False,
        time_window_seconds = 86400,    # 24시간
        bonus_score         = 65,
        severity            = RiskLevel.CRITICAL,
        required_count      = 2,
        narrative_template  = (
            "퇴직 처리된 사용자가 대규모 파일 접근·복사를 수행했습니다. "
            "퇴직 전 자료 무단 반출 고위험 시나리오입니다."
        ),
    ),

    CombinationRule(
        rule_id             = "C004",
        name                = "데이터 스테이징 후 외부 전송",
        patterns            = ["data_staging", "cloud_upload_unusual"],
        ordered             = True,
        time_window_seconds = 7200,     # 2시간
        bonus_score         = 50,
        severity            = RiskLevel.CRITICAL,
        narrative_template  = (
            "파일을 임시 위치에 모은 뒤 외부로 업로드했습니다. "
            "사전 계획된 데이터 유출 징후입니다."
        ),
    ),

    # ── Tier 2: 고위험 조합 (HIGH) ──────────────

    CombinationRule(
        rule_id             = "C005",
        name                = "비업무 시간 권한 상승",
        patterns            = ["after_hours_access", "privilege_escalation"],
        ordered             = True,
        time_window_seconds = 3600,
        bonus_score         = 40,
        severity            = RiskLevel.HIGH,
        narrative_template  = (
            "비업무 시간에 접근하여 권한 상승을 시도했습니다. "
            "감시가 느슨한 시간대를 노린 내부자 위협 패턴입니다."
        ),
    ),

    CombinationRule(
        rule_id             = "C006",
        name                = "정책 우회 후 파일 접근",
        patterns            = ["policy_bypass_attempt", "sensitive_file_access"],
        ordered             = True,
        time_window_seconds = 1800,
        bonus_score         = 45,
        severity            = RiskLevel.HIGH,
        narrative_template  = (
            "보안 정책을 우회한 직후 민감 파일에 접근했습니다. "
            "의도적 보안 회피 행위입니다."
        ),
    ),

    CombinationRule(
        rule_id             = "C007",
        name                = "신규 위치 접속 후 대량 다운로드",
        patterns            = ["vpn_from_new_location", "bulk_file_download"],
        ordered             = True,
        time_window_seconds = 3600,
        bonus_score         = 35,
        severity            = RiskLevel.HIGH,
        narrative_template  = (
            "평소와 다른 위치에서 접속하여 대량 파일을 다운로드했습니다. "
            "계정 탈취 또는 외부 공모 가능성이 있습니다."
        ),
    ),

    CombinationRule(
        rule_id             = "C008",
        name                = "화면 캡처 + 이메일 발송",
        patterns            = ["screen_capture", "email_attachment_large"],
        ordered             = True,
        time_window_seconds = 1800,
        bonus_score         = 30,
        severity            = RiskLevel.HIGH,
        narrative_template  = (
            "화면 캡처 후 외부로 대용량 이메일을 발송했습니다. "
            "화면 기반 정보 유출 시도로 판단됩니다."
        ),
    ),

    # ── Tier 3: 중위험 조합 (MEDIUM) ────────────

    CombinationRule(
        rule_id             = "C009",
        name                = "반복 인증 실패 후 관리 도구 사용",
        patterns            = ["multiple_failed_login", "admin_tool_usage"],
        ordered             = True,
        time_window_seconds = 900,     # 15분
        bonus_score         = 25,
        severity            = RiskLevel.MEDIUM,
        narrative_template  = (
            "반복 인증 실패 후 관리자 도구를 실행했습니다. "
            "무차별 대입 공격 후 횡적 이동 시도 가능성이 있습니다."
        ),
    ),

    CombinationRule(
        rule_id             = "C010",
        name                = "USB 연결 + 의심 네트워크 통신",
        patterns            = ["usb_connected", "suspicious_network_conn"],
        ordered             = False,
        time_window_seconds = 3600,
        bonus_score         = 20,
        severity            = RiskLevel.MEDIUM,
        narrative_template  = (
            "USB 장치 연결과 함께 의심 네트워크 통신이 발생했습니다. "
            "물리·논리 복합 유출 경로 사용 가능성이 있습니다."
        ),
    ),
]


# ──────────────────────────────────────────────
# 시간 감쇠(Time Decay) 설정
# ──────────────────────────────────────────────

@dataclass(frozen=True)
class TimeDecayConfig:
    half_life_hours: float      # 점수가 절반이 되는 시간 (시간 단위)
    min_retention: float        # 최소 유지 비율 (0.0 ~ 1.0)
    max_age_hours: float        # 이 시간 이상 지난 이벤트는 무시


TIME_DECAY_CONFIG = TimeDecayConfig(
    half_life_hours = 24.0,     # 24시간마다 점수 절반 감쇠
    min_retention   = 0.10,     # 최소 10% 유지
    max_age_hours   = 168.0,    # 7일 이상 된 이벤트 제외
)


# ──────────────────────────────────────────────
# 반복 발생 빈도 가중치
# ──────────────────────────────────────────────

FREQUENCY_MULTIPLIER: dict[int, float] = {
    1: 1.0,     # 1회: 기본
    2: 1.2,     # 2회: +20%
    3: 1.4,     # 3회: +40%
    4: 1.6,     # 4회: +60%
    5: 1.8,     # 5회: +80%
}
FREQUENCY_MAX_MULTIPLIER = 2.0  # 6회 이상: 2배 고정


def get_frequency_multiplier(count: int) -> float:
    if count <= 0:
        return 0.0
    return FREQUENCY_MULTIPLIER.get(count, FREQUENCY_MAX_MULTIPLIER)


# ──────────────────────────────────────────────
# 위험 등급 임계값
# ──────────────────────────────────────────────

SEVERITY_THRESHOLDS: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL : 90,
    RiskLevel.HIGH     : 70,
    RiskLevel.MEDIUM   : 40,
    RiskLevel.LOW      : 10,
    RiskLevel.NONE     : 0,
}


def score_to_level(score: float) -> RiskLevel:
    s = int(score)
    if s >= SEVERITY_THRESHOLDS[RiskLevel.CRITICAL]:
        return RiskLevel.CRITICAL
    elif s >= SEVERITY_THRESHOLDS[RiskLevel.HIGH]:
        return RiskLevel.HIGH
    elif s >= SEVERITY_THRESHOLDS[RiskLevel.MEDIUM]:
        return RiskLevel.MEDIUM
    elif s >= SEVERITY_THRESHOLDS[RiskLevel.LOW]:
        return RiskLevel.LOW
    return RiskLevel.NONE