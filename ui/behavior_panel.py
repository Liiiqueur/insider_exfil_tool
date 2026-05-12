from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from core.behavior import BehaviorPattern
    from core.correlator import Correlation


_RISK_COLOR = {
    "critical": "#FF4444",
    "high": "#FF8800",
    "medium": "#FFCC00",
    "low": "#44AAFF",
}

_RISK_BG = {
    "critical": "#2D0000",
    "high": "#2D1800",
    "medium": "#2B2500",
    "low": "#001A2D",
}

_RISK_LABEL = {
    "critical": "위험",
    "high": "높음",
    "medium": "보통",
    "low": "낮음",
}

_CONFIDENCE_COLOR = {
    "high": "#FF6666",
    "medium": "#FFAA44",
    "low": "#AAAAAA",
}

_CONFIDENCE_LABEL = {
    "high": "높음",
    "medium": "중간",
    "low": "낮음",
}


class SummaryBar(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)

        title = QLabel("행위 패턴 탐지")
        title.setFont(QFont("", 11, QFont.Bold))

        layout.addWidget(title)
        layout.addStretch()

        self.labels = {}

        for risk in ["critical", "high", "medium", "low"]:
            lbl = QLabel(f"{_RISK_LABEL[risk]}: 0")
            lbl.setStyleSheet(
                f"""
                color: {_RISK_COLOR[risk]};
                font-weight: bold;
                """
            )
            self.labels[risk] = lbl
            layout.addWidget(lbl)

        self.corr_lbl = QLabel("상관관계: 0")
        layout.addWidget(self.corr_lbl)

    def update_summary(self, patterns, correlations):

        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for p in patterns:
            counts[p.risk_level] += 1

        for risk, lbl in self.labels.items():
            lbl.setText(f"{_RISK_LABEL[risk]}: {counts[risk]}")

        self.corr_lbl.setText(f"상관관계: {len(correlations)}")


class PatternTable(QTableWidget):

    pattern_selected = pyqtSignal(object)

    def __init__(self):
        super().__init__(0, 5)

        self.setHorizontalHeaderLabels([
            "심각도",
            "패턴명",
            "이벤트 수",
            "탐지 시각",
            "소스",
        ])

        self.verticalHeader().setVisible(False)

        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)

        hdr = self.horizontalHeader()
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)

        self._patterns = []

        self.itemSelectionChanged.connect(self._on_select)

    def load(self, patterns):

        self._patterns = patterns
        self.setRowCount(0)

        for p in patterns:

            row = self.rowCount()
            self.insertRow(row)

            color = QColor(_RISK_COLOR.get(p.risk_level, "#FFFFFF"))
            bg = QColor(_RISK_BG.get(p.risk_level, "#111111"))

            values = [
                _RISK_LABEL.get(p.risk_level, p.risk_level),
                p.name,
                str(len(p.matched_events)),
                _fmt_dt(p.detected_at),
                ", ".join(sorted({
                    e.get("source", "")
                    for e in p.matched_events
                }))
            ]

            for col, val in enumerate(values):

                item = QTableWidgetItem(str(val))

                item.setForeground(color)
                item.setBackground(bg)

                self.setItem(row, col, item)

    def _on_select(self):

        rows = self.selectionModel().selectedRows()

        if not rows:
            return

        idx = rows[0].row()

        if 0 <= idx < len(self._patterns):
            self.pattern_selected.emit(self._patterns[idx])


class CorrelationTable(QTableWidget):

    correlation_selected = pyqtSignal(object)

    def __init__(self):

        super().__init__(0, 5)

        self.setHorizontalHeaderLabels([
            "신뢰도",
            "유형",
            "설명",
            "이벤트 수",
            "소스",
        ])

        self.verticalHeader().setVisible(False)

        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)

        hdr = self.horizontalHeader()
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)

        self._correlations = []

        self.itemSelectionChanged.connect(self._on_select)

    def load(self, correlations):

        self._correlations = correlations

        self.setRowCount(0)

        for c in correlations:

            row = self.rowCount()
            self.insertRow(row)

            conf = getattr(c, "confidence", "low")

            values = [
                conf,
                getattr(c, "correlation_type", ""),
                getattr(c, "description", ""),
                str(len(getattr(c, "events", []))),
                ", ".join(sorted({
                    e.get("source", "")
                    for e in getattr(c, "events", [])
                }))
            ]

            for col, val in enumerate(values):

                item = QTableWidgetItem(str(val))

                item.setForeground(
                    QColor(_CONFIDENCE_COLOR.get(conf, "#FFFFFF"))
                )

                self.setItem(row, col, item)

    def _on_select(self):

        rows = self.selectionModel().selectedRows()

        if not rows:
            return

        idx = rows[0].row()

        if 0 <= idx < len(self._correlations):
            self.correlation_selected.emit(
                self._correlations[idx]
            )


class DetailPanel(QWidget):

    def __init__(self):

        super().__init__()

        layout = QVBoxLayout(self)

        self.title = QLabel("선택된 항목 없음")
        self.title.setFont(QFont("", 10, QFont.Bold))

        layout.addWidget(self.title)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)

        layout.addWidget(sep)

        self.description = QLabel()
        self.description.setWordWrap(True)

        layout.addWidget(self.description)

        self.events = QTextEdit()
        self.events.setReadOnly(True)

        layout.addWidget(self.events)

    def show_pattern(self, pattern):

        self.title.setText(pattern.name)
        self.description.setText(pattern.description)

        lines = []

        for ev in pattern.matched_events:

            ts = ev.get("timestamp")

            lines.append(
                f"{ts} | "
                f"{ev.get('source')} | "
                f"{ev.get('description')}"
            )

        self.events.setPlainText("\n".join(lines))

    def show_correlation(self, correlation):

        self.title.setText(
            getattr(correlation, "correlation_type", "")
        )

        self.description.setText(
            getattr(correlation, "description", "")
        )

        lines = []

        for ev in getattr(correlation, "events", []):

            ts = ev.get("timestamp")

            lines.append(
                f"{ts} | "
                f"{ev.get('source')} | "
                f"{ev.get('description')}"
            )

        self.events.setPlainText("\n".join(lines))


class BehaviorPanel(QWidget):

    def __init__(self, parent=None):

        super().__init__(parent)

        root = QVBoxLayout(self)

        self.summary_bar = SummaryBar()
        root.addWidget(self.summary_bar)

        btn_layout = QHBoxLayout()

        self.run_btn = QPushButton("분석 실행")

        btn_layout.addStretch()
        btn_layout.addWidget(self.run_btn)

        root.addLayout(btn_layout)

        splitter = QSplitter(Qt.Vertical)

        top_split = QSplitter(Qt.Horizontal)

        self.pattern_table = PatternTable()
        self.corr_table = CorrelationTable()

        top_split.addWidget(self.pattern_table)
        top_split.addWidget(self.corr_table)

        splitter.addWidget(top_split)

        self.detail = DetailPanel()

        scroll = QScrollArea()
        scroll.setWidget(self.detail)
        scroll.setWidgetResizable(True)

        splitter.addWidget(scroll)

        splitter.setSizes([500, 250])

        root.addWidget(splitter)

        self.pattern_table.pattern_selected.connect(
            self.detail.show_pattern
        )

        self.corr_table.correlation_selected.connect(
            self.detail.show_correlation
        )

    def load(self, patterns, correlations):

        self.summary_bar.update_summary(
            patterns,
            correlations,
        )

        self.pattern_table.load(patterns)
        self.corr_table.load(correlations)

    def connect_run(self, slot):
        self.run_btn.clicked.connect(slot)


def _fmt_dt(dt):

    if not isinstance(dt, datetime):
        return "N/A"

    return dt.strftime("%Y-%m-%d %H:%M:%S")