from __future__ import annotations

from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# ── 색상 상수 (constants.py가 없어도 단독 동작) ──────────────
try:
    from .constants import C_TEXT, C_SUBTEXT, C_RED, C_AMBER, C_BLUE
except ImportError:
    C_TEXT    = "#e2e8f0"
    C_SUBTEXT = "#94a3b8"
    C_RED     = "#f87171"
    C_AMBER   = "#fbbf24"
    C_BLUE    = "#60a5fa"

# ── risk_rules 임포트 ─────────────────────────────────────────
try:
    from core.risk_rules import RiskLevel
except ImportError:
    class RiskLevel:  # type: ignore
        CRITICAL = "CRITICAL"
        HIGH     = "HIGH"
        MEDIUM   = "MEDIUM"
        LOW      = "LOW"
        NONE     = "NONE"


# ─────────────────────────────────────────────────────────────
# 색상 팔레트
# ─────────────────────────────────────────────────────────────

_LEVEL_COLOR: dict[str, str] = {
    "CRITICAL": "#f87171",
    "HIGH"    : "#fbbf24",
    "MEDIUM"  : "#facc15",
    "LOW"     : "#4ade80",
    "NONE"    : "#64748b",
}

_LEVEL_BG: dict[str, str] = {
    "CRITICAL": "#450a0a",
    "HIGH"    : "#431407",
    "MEDIUM"  : "#422006",
    "LOW"     : "#052e16",
    "NONE"    : "#1e293b",
}

_CAT_COLOR: dict[str, str] = {
    "data_exfiltration": "#f87171",
    "device_usage"     : "#fbbf24",
    "access_anomaly"   : "#60a5fa",
    "credential_abuse" : "#c084fc",
    "communication"    : "#34d399",
    "reconnaissance"   : "#818cf8",
    "policy_violation" : "#94a3b8",
}


# ─────────────────────────────────────────────────────────────
# 헬퍼: 셀 생성
# ─────────────────────────────────────────────────────────────

def _cell(text: str, color: str = C_TEXT, bold: bool = False, align=Qt.AlignLeft) -> QTableWidgetItem:
    item = QTableWidgetItem(str(text))
    item.setForeground(QColor(color))
    item.setTextAlignment(int(align) | Qt.AlignVCenter)
    item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
    if bold:
        f = item.font()
        f.setBold(True)
        item.setFont(f)
    return item


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        "color: #64748b; font-size: 11px; font-weight: 600;"
        "letter-spacing: 0.08em; padding: 8px 0 4px 0;"
    )
    return lbl


# ─────────────────────────────────────────────────────────────
# 메인 위젯
# ─────────────────────────────────────────────────────────────

class RiskReportPanel(QWidget):

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._build_ui()

    # ── UI 구성 ──────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 8, 12, 8)
        root.setSpacing(0)

        # ── 상단 요약 바 ─────────────────────────────────────
        root.addWidget(self._build_summary_bar())
        root.addSpacing(8)

        # ── 서브탭 ───────────────────────────────────────────
        self._tabs = QTabWidget()
        self._tabs.setObjectName("result_tabs")
        self._tabs.addTab(self._build_patterns_tab(),  "탐지 패턴")
        self._tabs.addTab(self._build_combos_tab(),    "조합 규칙")
        self._tabs.addTab(self._build_breakdown_tab(), "점수 내역")
        self._tabs.addTab(self._build_narrative_tab(), "내러티브 & 권고")
        root.addWidget(self._tabs, stretch=1)

    def _build_summary_bar(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("summary_bar")
        frame.setStyleSheet(
            "QFrame#summary_bar {"
            "  background: #1e293b;"
            "  border: 1px solid #334155;"
            "  border-radius: 6px;"
            "  padding: 6px;"
            "}"
        )
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(16)

        # 대상 ID
        self._subject_lbl = QLabel("대상: —")
        self._subject_lbl.setStyleSheet("color: #94a3b8; font-size: 12px;")
        layout.addWidget(self._subject_lbl)

        layout.addStretch(1)

        # 점수 숫자
        self._score_lbl = QLabel("—")
        self._score_lbl.setStyleSheet(
            "color: #e2e8f0; font-size: 28px; font-weight: 700;"
        )
        layout.addWidget(self._score_lbl)

        # 게이지
        self._gauge = QProgressBar()
        self._gauge.setRange(0, 100)
        self._gauge.setValue(0)
        self._gauge.setTextVisible(False)
        self._gauge.setFixedWidth(180)
        self._gauge.setFixedHeight(10)
        layout.addWidget(self._gauge)

        # 위험 등급 뱃지
        self._level_lbl = QLabel("NONE")
        self._level_lbl.setAlignment(Qt.AlignCenter)
        self._level_lbl.setFixedWidth(90)
        self._level_lbl.setStyleSheet(
            "border-radius: 4px; padding: 4px 8px;"
            "font-weight: 700; font-size: 13px;"
        )
        layout.addWidget(self._level_lbl)

        # 패턴 / 조합 카운터
        self._counter_lbl = QLabel("패턴 0  |  조합 0")
        self._counter_lbl.setStyleSheet("color: #94a3b8; font-size: 12px;")
        layout.addWidget(self._counter_lbl)

        return frame

    # ── 탐지 패턴 탭 ─────────────────────────────────────────

    def _build_patterns_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(0)

        self._pattern_table = QTableWidget()
        self._pattern_table.setColumnCount(7)
        self._pattern_table.setHorizontalHeaderLabels([
            "패턴 ID", "카테고리", "MITRE", "발생 횟수",
            "감쇠(%)", "빈도 배수", "기여 점수"
        ])
        self._pattern_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._pattern_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._pattern_table.setSortingEnabled(True)
        self._pattern_table.setAlternatingRowColors(True)
        self._pattern_table.verticalHeader().setVisible(False)
        self._pattern_table.setShowGrid(False)
        hdr = self._pattern_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        layout.addWidget(self._pattern_table, stretch=1)
        return page

    # ── 조합 규칙 탭 ─────────────────────────────────────────

    def _build_combos_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(0)

        self._combo_table = QTableWidget()
        self._combo_table.setColumnCount(5)
        self._combo_table.setHorizontalHeaderLabels([
            "규칙 ID", "조합 이름", "매칭 패턴", "발생 구간", "보너스 점수"
        ])
        self._combo_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._combo_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._combo_table.setSortingEnabled(False)
        self._combo_table.setAlternatingRowColors(True)
        self._combo_table.verticalHeader().setVisible(False)
        self._combo_table.setShowGrid(False)
        hdr = self._combo_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)

        # 조합 내러티브 상세
        self._combo_detail = QTextEdit()
        self._combo_detail.setReadOnly(True)
        self._combo_detail.setFixedHeight(90)
        self._combo_detail.setPlaceholderText("조합 행을 선택하면 내러티브가 표시됩니다.")
        self._combo_table.currentCellChanged.connect(self._on_combo_selected)

        layout.addWidget(self._combo_table, stretch=1)
        layout.addWidget(_section_label("  선택된 조합 내러티브"))
        layout.addWidget(self._combo_detail)
        return page

    # ── 점수 내역 탭 ─────────────────────────────────────────

    def _build_breakdown_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(6)

        self._bd_labels: dict[str, QLabel] = {}
        rows = [
            ("base_pattern_score",     "단일 패턴 합계 (원점수)"),
            ("adjusted_pattern_score", "단일 패턴 합계 (감쇠·빈도 조정 후)"),
            ("combo_bonus_score",      "조합 보너스 합계"),
            ("raw_total",              "합산 (캡핑 전)"),
            ("final_score",            "최종 점수 (0–100)"),
        ]
        for key, label in rows:
            row_w = QWidget()
            row_l = QHBoxLayout(row_w)
            row_l.setContentsMargins(0, 4, 0, 4)
            lbl_k = QLabel(label)
            lbl_k.setStyleSheet("color: #94a3b8;")
            lbl_v = QLabel("—")
            lbl_v.setAlignment(Qt.AlignRight)
            is_final = key == "final_score"
            lbl_v.setStyleSheet(
                f"color: {'#e2e8f0' if not is_final else '#fbbf24'};"
                f"font-weight: {'700' if is_final else '400'};"
                f"font-size: {'15px' if is_final else '13px'};"
            )
            self._bd_labels[key] = lbl_v
            row_l.addWidget(lbl_k, stretch=1)
            row_l.addWidget(lbl_v)

            sep = QFrame()
            sep.setFrameShape(QFrame.HLine)
            sep.setStyleSheet("color: #1e293b;")

            layout.addWidget(row_w)
            if key != "final_score":
                layout.addWidget(sep)

        layout.addStretch(1)
        return page

    # ── 내러티브 & 권고 탭 ───────────────────────────────────

    def _build_narrative_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Vertical)

        # 내러티브 텍스트
        narrative_w = QWidget()
        nw_layout   = QVBoxLayout(narrative_w)
        nw_layout.setContentsMargins(8, 0, 8, 0)
        nw_layout.addWidget(_section_label("내러티브"))
        self._narrative_text = QTextEdit()
        self._narrative_text.setReadOnly(True)
        self._narrative_text.setPlaceholderText("Correlate를 실행하면 내러티브가 생성됩니다.")
        nw_layout.addWidget(self._narrative_text)

        # 권고 조치
        rec_w    = QWidget()
        rec_layout = QVBoxLayout(rec_w)
        rec_layout.setContentsMargins(8, 0, 8, 4)
        rec_layout.addWidget(_section_label("권고 조치"))
        self._rec_list = QListWidget()
        self._rec_list.setAlternatingRowColors(True)
        self._rec_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        rec_layout.addWidget(self._rec_list)

        splitter.addWidget(narrative_w)
        splitter.addWidget(rec_w)
        splitter.setSizes([300, 200])
        layout.addWidget(splitter, stretch=1)
        return page

    # ── 데이터 주입 ──────────────────────────────────────────

    def load(self, report) -> None:
        if report is None:
            self.clear()
            return

        self._load_summary(report)
        self._load_patterns(report)
        self._load_combos(report)
        self._load_breakdown(report)
        self._load_narrative(report)

    def clear(self) -> None:
        self._subject_lbl.setText("대상: —")
        self._score_lbl.setText("—")
        self._gauge.setValue(0)
        self._gauge.setStyleSheet("")
        self._level_lbl.setText("NONE")
        self._level_lbl.setStyleSheet(
            f"background: {_LEVEL_BG['NONE']}; color: {_LEVEL_COLOR['NONE']};"
            "border-radius: 4px; padding: 4px 8px;"
            "font-weight: 700; font-size: 13px;"
        )
        self._counter_lbl.setText("패턴 0  |  조합 0")
        self._pattern_table.setRowCount(0)
        self._combo_table.setRowCount(0)
        self._combo_detail.clear()
        for lbl in self._bd_labels.values():
            lbl.setText("—")
        self._narrative_text.clear()
        self._rec_list.clear()

    # ── 내부 로드 메서드 ─────────────────────────────────────

    def _load_summary(self, report) -> None:
        level = getattr(report.risk_level, "value", str(report.risk_level))
        score = round(report.score, 1)
        color = _LEVEL_COLOR.get(level, "#64748b")
        bg    = _LEVEL_BG.get(level,    "#1e293b")

        self._subject_lbl.setText(f"대상: {report.subject_id}")
        self._score_lbl.setText(f"{score}")
        self._score_lbl.setStyleSheet(
            f"color: {color}; font-size: 28px; font-weight: 700;"
        )
        self._gauge.setValue(int(score))
        self._gauge.setStyleSheet(
            f"QProgressBar::chunk {{ background: {color}; border-radius: 4px; }}"
            "QProgressBar { background: #334155; border-radius: 4px; border: none; }"
        )
        self._level_lbl.setText(level)
        self._level_lbl.setStyleSheet(
            f"background: {bg}; color: {color};"
            "border-radius: 4px; padding: 4px 8px;"
            "font-weight: 700; font-size: 13px;"
        )
        p_cnt = len(report.detected_patterns)
        c_cnt = len(report.triggered_combos)
        self._counter_lbl.setText(f"패턴 {p_cnt}  |  조합 {c_cnt}")

    def _load_patterns(self, report) -> None:
        patterns = sorted(
            report.detected_patterns,
            key=lambda p: p.effective_score,
            reverse=True,
        )
        self._pattern_table.setSortingEnabled(False)
        self._pattern_table.setRowCount(len(patterns))
        for row, p in enumerate(patterns):
            cat_color = _CAT_COLOR.get(p.category, C_SUBTEXT)
            decay_pct = f"{int(p.time_decay_factor * 100)}%"
            freq_str  = f"×{p.frequency_multiplier:.1f}"
            eff_str   = f"{p.effective_score:.1f}"

            self._pattern_table.setItem(row, 0, _cell(p.display_name))
            self._pattern_table.setItem(row, 1, _cell(p.category, cat_color))
            self._pattern_table.setItem(row, 2, _cell(p.mitre_technique or "—", C_SUBTEXT))
            self._pattern_table.setItem(row, 3, _cell(str(p.occurrence_count), align=Qt.AlignRight))
            self._pattern_table.setItem(row, 4, _cell(decay_pct, C_SUBTEXT, align=Qt.AlignRight))
            self._pattern_table.setItem(row, 5, _cell(freq_str, C_SUBTEXT, align=Qt.AlignRight))

            level = getattr(report.risk_level, "value", str(report.risk_level))
            score_color = _LEVEL_COLOR.get(level, C_TEXT)
            self._pattern_table.setItem(
                row, 6, _cell(eff_str, score_color, bold=True, align=Qt.AlignRight)
            )
        self._pattern_table.setSortingEnabled(True)

    def _load_combos(self, report) -> None:
        combos = report.triggered_combos
        self._combo_table.setRowCount(len(combos))
        self._combos_ref = combos  # 내러티브 상세용
        for row, tc in enumerate(combos):
            rule = tc.rule
            matched_str = " → ".join(tc.matched_patterns)
            self._combo_table.setItem(row, 0, _cell(rule.rule_id, C_SUBTEXT))
            self._combo_table.setItem(row, 1, _cell(rule.name, C_AMBER, bold=True))
            self._combo_table.setItem(row, 2, _cell(matched_str))
            self._combo_table.setItem(row, 3, _cell(tc.time_span_str, C_SUBTEXT))
            self._combo_table.setItem(
                row, 4, _cell(f"+{tc.bonus_score}", C_RED, bold=True, align=Qt.AlignRight)
            )

    def _load_breakdown(self, report) -> None:
        bd = report.breakdown
        for key, lbl in self._bd_labels.items():
            val = getattr(bd, key, None)
            if val is None:
                lbl.setText("—")
            else:
                lbl.setText(f"{val:.1f}점")

    def _load_narrative(self, report) -> None:
        self._narrative_text.setPlainText(report.narrative or "내러티브 없음")
        self._rec_list.clear()
        for i, rec in enumerate(report.recommendations, 1):
            item = QListWidgetItem(f"  {i}. {rec}")
            item.setForeground(QColor(C_TEXT))
            self._rec_list.addItem(item)

    # ── 슬롯 ─────────────────────────────────────────────────

    def _on_combo_selected(self, row: int, *_) -> None:
        combos = getattr(self, "_combos_ref", [])
        if 0 <= row < len(combos):
            self._combo_detail.setPlainText(combos[row].rule.narrative_template)
        else:
            self._combo_detail.clear()