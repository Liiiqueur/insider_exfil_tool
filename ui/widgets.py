import json
import os
from datetime import datetime, timedelta
from typing import Optional

from PyQt5.QtCore import QSize, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QKeySequence, QPainter, QPen
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class SortableTableWidgetItem(QTableWidgetItem):

    def __init__(self, text: str, sort_value=None):
        super().__init__(text)
        self._sort_value = text if sort_value is None else sort_value

    def __lt__(self, other):
        if isinstance(other, SortableTableWidgetItem):
            return self._sort_value < other._sort_value
        return super().__lt__(other)


class CopyableTableWidget(QTableWidget):

    def keyPressEvent(self, event):
        if event.matches(QKeySequence.Copy):
            self._copy_selection()
            return
        super().keyPressEvent(event)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        copy_action = menu.addAction("Copy")
        chosen = menu.exec_(event.globalPos())
        if chosen == copy_action:
            self._copy_selection()

    def _copy_selection(self):
        indexes = self.selectedIndexes()
        if not indexes:
            return
        rows = sorted({idx.row()    for idx in indexes})
        cols = sorted({idx.column() for idx in indexes})
        lines = []
        for row in rows:
            values = []
            for col in cols:
                cell = self.item(row, col)
                values.append(cell.text() if cell else "")
            lines.append("\t".join(values))
        QApplication.clipboard().setText("\n".join(lines))


class StartupDialog(QDialog):

    def __init__(self, recent_files: list[str], parent=None):
        super().__init__(parent)
        self.selected_path: str | None = None
        self.setWindowTitle("Open Evidence")
        self.setModal(True)
        self.setMinimumSize(560, 340)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setStyleSheet("""
            QDialog {
                background: #f5f7fa;
            }
            QLabel#startup_subtitle {
                color: #6b7280;
                font-size: 14px;
                font-weight: 600;
            }
            QListWidget {
                background: #ffffff;
                border: 1px solid #e1e5ea;
                border-radius: 10px;
                padding: 6px;
                outline: none;
            }
            QListWidget::item {
                color: #1f2933;
                border-radius: 8px;
                padding: 10px 12px;
                margin: 2px 0;
            }
            QListWidget::item:selected {
                background: #e6f0ff;
                color: #2563eb;
            }
            QListWidget::item:hover {
                background: #eef2f7;
            }
            QPushButton {
                min-height: 34px;
                border-radius: 8px;
                padding: 0 14px;
                font-weight: 600;
            }
            QPushButton#primary_open {
                background: #2563eb;
                color: white;
                border: none;
            }
            QPushButton#primary_open:hover {
                background: #1d4ed8;
            }
            QPushButton#secondary_open {
                background: #ffffff;
                color: #1f2933;
                border: 1px solid #d7dee7;
            }
            QPushButton#secondary_open:hover {
                background: #eef2f7;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        subtitle = QLabel("Choose a forensic image or double-click a recent file below.")
        subtitle.setObjectName("startup_subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        button_row = QHBoxLayout()
        open_btn = QPushButton("New Image")
        open_btn.setObjectName("primary_open")
        open_btn.clicked.connect(self._choose_open)
        button_row.addWidget(open_btn)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        self.recent_list = QListWidget()
        self.recent_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.recent_list.itemDoubleClicked.connect(lambda _: self._choose_recent())
        for path in recent_files[:3]:
            item = QListWidgetItem(path)
            item.setToolTip(path)
            self.recent_list.addItem(item)
        if self.recent_list.count():
            self.recent_list.setCurrentRow(0)
        else:
            empty = QListWidgetItem("No recent images")
            empty.setFlags(Qt.NoItemFlags)
            self.recent_list.addItem(empty)
        layout.addWidget(self.recent_list)

    # ── 내부 슬롯 ──────────────────────────────────────

    def _choose_open(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Image",
            "",
            "Disk Images (*.001 *.dd *.raw *.img);;"
            "EWF Images (*.E01 *.e01);;"
            "All Files (*)",
        )
        if not path:
            return
        self.selected_path = path
        self.accept()

    def _choose_recent(self):
        item = self.recent_list.currentItem()
        if not item:
            return
        self.selected_path = item.text()
        self.accept()


class TimelineHistogramWidget(QWidget):
    bucket_selected = pyqtSignal(int)
    _BAR_STEP = 34
    _BAR_WIDTH = 24
    _LEFT_PAD = 58
    _RIGHT_PAD = 30
    _VIEW_MODES = ("Year", "Month", "Day")

    _CATEGORY_MAP: dict[str, set[str]] = {
        "All": set(),
        "File Activity": {"filesystem", "lnk", "jumplist", "recentdocs", "shellbags"},
        "Web Activity": {"browser_artifacts"},
        "USB Activity": {"usb", "mounteddevices"},
        "Mail Activity": {"ost_pst"},
        "Execution Activity": {"userassist", "prefetch", "amcache"},
    }

    _CATEGORY_COLORS: dict[str, QColor] = {
        "File Activity": QColor("#f59e0b"),
        "Web Activity": QColor("#059669"),
        "USB Activity": QColor("#f97316"),
        "Mail Activity": QColor("#0f766e"),
        "Execution Activity": QColor("#2563eb"),
        "Other": QColor("#94a3b8"),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_events: list[dict] = []
        self._events: list[dict] = []
        self._filter_text = "All"
        self._view_mode = "Day"
        self._range_start: Optional[datetime] = None
        self._range_end: Optional[datetime] = None
        self._buckets: list[dict] = []
        self._selected_bucket = -1
        self._hovered_bucket = -1
        self._bar_rects: list[tuple[int, int, int, int]] = []
        self.setMinimumHeight(300)
        self.setMinimumWidth(320)
        self.setMouseTracking(True)

    def set_events(self, events: list[dict]) -> None:
        self._all_events = list(events)
        self._recompute_range_bounds()
        self.apply_filter(self._filter_text)

    def apply_filter(self, filter_text: str) -> None:
        self._filter_text = filter_text
        allowed = self._CATEGORY_MAP.get(filter_text, set())
        if not allowed:
            self._events = list(self._all_events)
        else:
            self._events = [
                event for event in self._all_events
                if event.get("artifact_type") in allowed
            ]
        self._rebuild_buckets()
        self.update()

    def set_view_mode(self, view_mode: str) -> None:
        if view_mode not in self._VIEW_MODES:
            view_mode = "Day"
        if self._view_mode == view_mode:
            return
        self._view_mode = view_mode
        self._recompute_range_bounds()
        self._rebuild_buckets()
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor("#f8fafc"))
        self._bar_rects = []

        left = self._LEFT_PAD
        right = max(left + 200, self.width() - self._RIGHT_PAD)
        top = 26
        bottom = self.height() - 96

        painter.setPen(QColor("#334155"))
        painter.drawText(left, 16, "Activity Counts")

        if not self._buckets:
            painter.drawText(left, top + 36, "No timeline events")
            return

        max_count = max(bucket["total"] for bucket in self._buckets) or 1
        axis_y = bottom

        painter.setPen(QPen(QColor("#cbd5e1"), 1))
        painter.drawLine(left, axis_y, right, axis_y)

        for index, bucket in enumerate(self._buckets):
            x = left + index * self._BAR_STEP
            bar_width = self._BAR_WIDTH
            total_height = max(1, int((bucket["total"] / max_count) * (bottom - top - 10)))
            y = axis_y

            if index == self._selected_bucket:
                painter.fillRect(x - 2, top - 6, bar_width + 4, bottom - top + 12, QColor("#e6f0ff"))

            if bucket["total"] == 0:
                painter.fillRect(x, axis_y - 4, bar_width, 4, QColor("#d1d5db"))

            for category in ("File Activity", "Web Activity", "USB Activity", "Mail Activity", "Execution Activity", "Other"):
                count = bucket["counts"].get(category, 0)
                if not count:
                    continue
                segment_height = max(3, int((count / max_count) * (bottom - top - 10)))
                y -= segment_height
                painter.fillRect(x, y, bar_width, segment_height, self._CATEGORY_COLORS[category])

            painter.setPen(QColor("#64748b"))
            axis_label = self._get_axis_label(index)
            if axis_label:
                painter.drawText(x - 10, axis_y + 18, self._BAR_STEP + 20, 28, Qt.AlignHCenter | Qt.AlignTop, axis_label)
            if index == self._hovered_bucket:
                painter.setPen(QColor("#2563eb"))
                painter.drawText(
                    x - 12,
                    axis_y + 48,
                    self._BAR_STEP + 24,
                    28,
                    Qt.AlignHCenter | Qt.AlignTop,
                    self._get_hover_label(bucket),
                )
            self._bar_rects.append((x, top, bar_width, bottom - top))

    def mousePressEvent(self, event):
        pos = event.pos()
        for index, (x, y, w, h) in enumerate(self._bar_rects):
            if x <= pos.x() <= x + w and y <= pos.y() <= y + h:
                self._selected_bucket = index
                self.bucket_selected.emit(index)
                self.update()
                return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        pos = event.pos()
        hovered_index = -1
        for index, (x, y, w, h) in enumerate(self._bar_rects):
            if x <= pos.x() <= x + w and y <= pos.y() <= y + h:
                hovered_index = index
                break
        if hovered_index != self._hovered_bucket:
            self._hovered_bucket = hovered_index
            self.update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event):
        if self._hovered_bucket != -1:
            self._hovered_bucket = -1
            self.update()
        super().leaveEvent(event)

    def select_bucket(self, index: int) -> None:
        if 0 <= index < len(self._buckets):
            self._selected_bucket = index
            self.update()

    def get_bucket_events(self, index: int) -> list[dict]:
        if 0 <= index < len(self._buckets):
            return self._buckets[index]["events"]
        return []

    def summary_text(self) -> str:
        if not self._events:
            return f"Events: 0  |  View: {self._view_mode}"
        if not self._buckets:
            return f"Events: {len(self._events)}  |  View: {self._view_mode}"
        first = self._buckets[0]["label"]
        last = self._buckets[-1]["label"]
        return (
            f"Events: {len(self._events)}  |  View: {self._view_mode}"
            f"  |  Buckets: {len(self._buckets)}  |  Range: {first} - {last}"
        )

    def _rebuild_buckets(self) -> None:
        self._buckets = []
        self._selected_bucket = -1
        self._hovered_bucket = -1
        if self._range_start is None or self._range_end is None:
            self.setFixedWidth(320)
            return

        bucket_map: dict[datetime, dict] = {}
        for event in self._events:
            start = self._bucket_start(event["timestamp"])
            end = self._bucket_end(start)
            bucket = bucket_map.setdefault(start, {
                "start": start,
                "end": end,
                "events": [],
                "counts": {},
                "total": 0,
                "label": self._format_bucket_label(start),
            })
            category = self._classify_category(event)
            bucket["events"].append(event)
            bucket["counts"][category] = bucket["counts"].get(category, 0) + 1
            bucket["total"] += 1

        current = self._range_start
        while current <= self._range_end:
            if current not in bucket_map:
                bucket_map[current] = {
                    "start": current,
                    "end": self._bucket_end(current),
                    "events": [],
                    "counts": {},
                    "total": 0,
                    "label": self._format_bucket_label(current),
                }
            current = self._bucket_end(current)

        self._buckets = [bucket_map[key] for key in sorted(bucket_map.keys())]
        if self._buckets:
            self._selected_bucket = len(self._buckets) - 1
        self.setFixedWidth(max(320, self._LEFT_PAD + self._RIGHT_PAD + len(self._buckets) * self._BAR_STEP))

    def _recompute_range_bounds(self) -> None:
        if self._all_events:
            timestamps = [event["timestamp"] for event in self._all_events]
            self._range_start = self._bucket_start(min(timestamps))
            self._range_end = self._bucket_start(max(timestamps))
        else:
            self._range_start = None
            self._range_end = None

    def _bucket_start(self, timestamp: datetime) -> datetime:
        if self._view_mode == "Year":
            return timestamp.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        if self._view_mode == "Month":
            return timestamp.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if self._view_mode == "Day":
            return timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
        return timestamp.replace(hour=0, minute=0, second=0, microsecond=0)

    def _bucket_end(self, start: datetime) -> datetime:
        if self._view_mode == "Year":
            return start.replace(year=start.year + 1)
        if self._view_mode == "Month":
            if start.month == 12:
                return start.replace(year=start.year + 1, month=1)
            return start.replace(month=start.month + 1)
        return start + timedelta(days=1)

    def _format_bucket_label(self, start: datetime) -> str:
        if self._view_mode == "Year":
            return start.strftime("%Y")
        if self._view_mode == "Month":
            return start.strftime("%Y-%m")
        return start.strftime("%m-%d")

    def _get_axis_label(self, index: int) -> str:
        bucket = self._buckets[index]
        start = bucket["start"]
        previous = self._buckets[index - 1]["start"] if index > 0 else None
        if self._view_mode == "Year":
            return start.strftime("%Y")
        if self._view_mode == "Month":
            if previous is None or previous.year != start.year:
                return start.strftime("%Y")
            return ""
        if previous is None or previous.month != start.month or previous.year != start.year:
            return start.strftime("%m")
        return ""

    def _get_hover_label(self, bucket: dict) -> str:
        start = bucket["start"]
        if self._view_mode == "Year":
            return start.strftime("%Y")
        if self._view_mode == "Month":
            return start.strftime("%Y/%m")
        return start.strftime("%m/%d")

    def _format_bucket_datetime(self, value: datetime) -> str:
        if self._view_mode == "Year":
            return value.strftime("%Y")
        if self._view_mode == "Month":
            return value.strftime("%Y-%m")
        return value.strftime("%Y-%m-%d")

    def _classify_category(self, event: dict) -> str:
        artifact_type = event.get("artifact_type")
        for label, artifacts in self._CATEGORY_MAP.items():
            if label != "All" and artifact_type in artifacts:
                return label
        return "Other"


class TimelineExplorerWidget(QWidget):
    _PAGE_SIZE = 50
    detail_navigation_requested = pyqtSignal(str, int)

    def __init__(self, events: list[dict] = None, parent=None):
        super().__init__(parent)
        self._pending_bucket_index: Optional[int] = None
        self._current_bucket_index: Optional[int] = None
        self._visible_count = 0
        self._visible_bucket_events: list[dict] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel("Integrated Timeline")
        title.setStyleSheet("font-weight: bold; font-size: 15px;")
        header.addWidget(title)
        header.addStretch(1)
        header.addWidget(QLabel("Filter"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "All",
            "File Activity",
            "Web Activity",
            "USB Activity",
            "Mail Activity",
            "Execution Activity",
        ])
        header.addWidget(self.filter_combo)
        header.addWidget(QLabel("View"))
        self.view_combo = QComboBox()
        self.view_combo.addItems(["Year", "Month", "Day"])
        self.view_combo.setCurrentText("Day")
        header.addWidget(self.view_combo)
        layout.addLayout(header)

        self.summary_label = QLabel()
        layout.addWidget(self.summary_label)

        self.histogram = TimelineHistogramWidget()
        self.histogram_scroll = QScrollArea()
        self.histogram_scroll.setWidgetResizable(False)
        self.histogram_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.histogram_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.histogram_scroll.setFrameShape(QFrame.NoFrame)
        self.histogram_scroll.setWidget(self.histogram)
        self.histogram_scroll.setMinimumHeight(270)
        layout.addWidget(self.histogram_scroll, stretch=0)

        content_split = QSplitter(Qt.Horizontal)
        list_panel = QWidget()
        list_layout = QVBoxLayout(list_panel)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(6)

        self.bucket_label = QLabel("Selected Range")
        self.bucket_label.setStyleSheet("font-weight: 600;")
        list_layout.addWidget(self.bucket_label)

        self.event_table = CopyableTableWidget()
        self.event_table.setColumnCount(4)
        self.event_table.setHorizontalHeaderLabels(["Time", "Category", "Action", "Target"])
        self.event_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.event_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.event_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.event_table.verticalHeader().setVisible(False)
        self.event_table.setAlternatingRowColors(True)
        self.event_table.setWordWrap(False)
        header = self.event_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        list_layout.addWidget(self.event_table, stretch=1)

        self.load_more_btn = QPushButton("Load More")
        self.load_more_btn.setVisible(False)
        self.load_more_btn.clicked.connect(self._load_more_events)
        list_layout.addWidget(self.load_more_btn)

        detail_panel = QWidget()
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(6)
        detail_title = QLabel("Details")
        detail_title.setStyleSheet("font-weight: 600;")
        detail_layout.addWidget(detail_title)
        self.detail_scroll = QScrollArea()
        self.detail_scroll.setWidgetResizable(True)
        self.detail_scroll.setFrameShape(QFrame.NoFrame)
        self.detail_widget = QWidget()
        self.detail_rows_layout = QVBoxLayout(self.detail_widget)
        self.detail_rows_layout.setContentsMargins(0, 0, 0, 0)
        self.detail_rows_layout.setSpacing(8)
        self.detail_rows_layout.addStretch(1)
        self.detail_scroll.setWidget(self.detail_widget)
        detail_layout.addWidget(self.detail_scroll, stretch=1)

        content_split.addWidget(list_panel)
        content_split.addWidget(detail_panel)
        content_split.setSizes([700, 420])
        layout.addWidget(content_split, stretch=1)

        self.filter_combo.currentTextChanged.connect(self._on_filter_changed)
        self.view_combo.currentTextChanged.connect(self._on_view_changed)
        self.histogram.bucket_selected.connect(self._on_bucket_selected)
        self.event_table.itemSelectionChanged.connect(self._on_event_selected)
        self.set_events(events or [])

    def set_events(self, events: list[dict]) -> None:
        self.histogram.set_events(events)
        self._reset_histogram_scroll()
        self._update_summary()
        if self.histogram._selected_bucket >= 0:
            self._on_bucket_selected(self.histogram._selected_bucket)

    def _on_filter_changed(self, value: str) -> None:
        self.histogram.apply_filter(value)
        self._reset_histogram_scroll()
        self._update_summary()
        if self.histogram._selected_bucket >= 0:
            self._on_bucket_selected(self.histogram._selected_bucket)
        else:
            self.event_table.setRowCount(0)
            self._clear_detail_rows()

    def _on_view_changed(self, value: str) -> None:
        self.histogram.set_view_mode(value)
        self._reset_histogram_scroll()
        self._update_summary()
        if self.histogram._selected_bucket >= 0:
            self._on_bucket_selected(self.histogram._selected_bucket)
        else:
            self.bucket_label.setText("Selected Range")
            self.event_table.setRowCount(0)
            self._clear_detail_rows()

    def _update_summary(self) -> None:
        self.summary_label.setText(self.histogram.summary_text())

    def _on_bucket_selected(self, index: int) -> None:
        self.histogram.select_bucket(index)
        self._pending_bucket_index = index
        self._current_bucket_index = index
        self._visible_count = self._PAGE_SIZE
        self.bucket_label.setText("Loading selected range...")
        self.event_table.blockSignals(True)
        self.event_table.clearContents()
        self.event_table.setRowCount(0)
        self.event_table.blockSignals(False)
        self.load_more_btn.setVisible(False)
        self._show_detail_message("Loading event list...")
        QTimer.singleShot(0, self._populate_selected_bucket)

    def _populate_selected_bucket(self) -> None:
        index = self._pending_bucket_index
        if index is None:
            return
        selected_row = self.event_table.currentRow()
        events = self.histogram.get_bucket_events(index)
        if not events:
            self.bucket_label.setText("Selected Range")
            self.event_table.setRowCount(0)
            self._clear_detail_rows()
            return

        bucket = self.histogram._buckets[index]
        visible_events = events[:self._visible_count]
        self._visible_bucket_events = visible_events
        visible_count = len(visible_events)
        self.bucket_label.setText(
            f"{bucket['label']}  |  {len(events)} events"
            + (f"  |  showing {visible_count}" if visible_count != len(events) else "")
        )
        self.event_table.blockSignals(True)
        self.event_table.setUpdatesEnabled(False)
        self.event_table.clearContents()
        self.event_table.setRowCount(len(visible_events))
        for row, event in enumerate(visible_events):
            values = [
                event["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                self.histogram._classify_category(event).replace(" Activity", ""),
                event.get("action", ""),
                event.get("summary") or event.get("target") or "",
            ]
            for col, value in enumerate(values):
                self.event_table.setItem(row, col, QTableWidgetItem(value))
        self.event_table.setUpdatesEnabled(True)
        self.event_table.blockSignals(False)
        self.event_table.viewport().update()
        has_more = len(events) > len(visible_events)
        self.load_more_btn.setVisible(has_more)
        if has_more:
            self.load_more_btn.setText(
                f"Load More ({len(events) - len(visible_events)} remaining)"
            )
        if visible_events:
            restore_row = selected_row if 0 <= selected_row < len(visible_events) else 0
            self.event_table.selectRow(restore_row)
            self._show_event_details(visible_events[restore_row])
        else:
            self._clear_detail_rows()

    def _on_event_selected(self) -> None:
        row = self.event_table.currentRow()
        if 0 <= row < len(self._visible_bucket_events):
            self._show_event_details(self._visible_bucket_events[row])

    def _load_more_events(self) -> None:
        if self._current_bucket_index is None:
            return
        self._visible_count += self._PAGE_SIZE
        self.bucket_label.setText("Loading more events...")
        QTimer.singleShot(0, self._populate_selected_bucket)

    def _show_event_details(self, event: dict) -> None:
        detail = event.get("detail", {}) or {}
        self._clear_detail_rows()
        self._add_detail_row("Time", event.get("timestamp").strftime("%Y-%m-%d %H:%M:%S") if event.get("timestamp") else "")
        self._add_detail_row("Artifact", event.get("artifact_type", ""))
        self._add_detail_row("Category", self.histogram._classify_category(event))
        self._add_detail_row("Action", event.get("action", ""))
        self._add_detail_row("Target", event.get("target", ""))
        self._add_detail_row("Source", event.get("source", ""))
        self._add_detail_row("Summary", event.get("summary", ""))

        derived_source_path = detail.get("source_path")
        if not derived_source_path:
            target = event.get("target")
            if isinstance(target, str) and target.startswith("/"):
                derived_source_path = target
        if derived_source_path:
            self._add_detail_row("Source Path", str(derived_source_path), (str(derived_source_path), 0))

        offset_keys = ("file_offset", "offset", "logical_offset", "physical_offset")
        for offset_key in offset_keys:
            if offset_key in detail:
                offset_text = self._detail_value_to_text(detail, offset_key)
                nav = self._detail_navigation_target(event, detail, offset_key, offset_text)
                self._add_detail_row(self._detail_label(offset_key), offset_text, nav)
                break

        for key in sorted(detail.keys()):
            if key == "source_path" or key in offset_keys:
                continue
            text = self._detail_value_to_text(detail, key)
            if len(text) > 240:
                text = text[:240] + " ..."
            nav = self._detail_navigation_target(event, detail, key, text)
            self._add_detail_row(self._detail_label(key), text, nav)

    def _clear_detail_rows(self) -> None:
        while self.detail_rows_layout.count() > 1:
            item = self.detail_rows_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _show_detail_message(self, message: str) -> None:
        self._clear_detail_rows()
        self._add_detail_row("", message)

    def _add_detail_row(self, label: str, value: str, nav_target=None) -> None:
        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(10)

        label_widget = QLabel(label)
        label_widget.setAlignment(Qt.AlignRight | Qt.AlignTop)
        label_widget.setStyleSheet("color: #94a3b8; font-weight: 600;")
        label_widget.setFixedWidth(120)
        row_layout.addWidget(label_widget)

        value_widget = QLabel()
        value_widget.setWordWrap(True)
        value_widget.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        value_widget.setStyleSheet("color: #1f2933; font-weight: 700;")
        value_widget.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        if nav_target is not None:
            path, offset = nav_target
            value_widget.setText(
                f'<a href="nav://open" style="color:#2563eb; text-decoration:none;">{value}</a>'
            )
            value_widget.setTextFormat(Qt.RichText)
            value_widget.setTextInteractionFlags(
                Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard | Qt.LinksAccessibleByMouse
            )
            value_widget.setStyleSheet("color: #2563eb; font-weight: 700;")
            value_widget.linkActivated.connect(
                lambda _href, p=path, o=offset: self.detail_navigation_requested.emit(p, o)
            )
        else:
            value_widget.setText(value)
        row_layout.addWidget(value_widget, stretch=1)
        self.detail_rows_layout.insertWidget(self.detail_rows_layout.count() - 1, row_widget)

    def _detail_value_to_text(self, detail: dict, key: str) -> str:
        value = detail.get(key)
        if isinstance(value, list):
            if key == "attachments":
                text = ", ".join(
                    item.get("name", "") for item in value[:8] if isinstance(item, dict)
                )
                if len(value) > 8:
                    text += f" ... (+{len(value) - 8})"
                return text
            return f"{len(value)} item(s)"
        if isinstance(value, dict):
            return json.dumps(value, ensure_ascii=False, default=str)
        return str(value)

    def _detail_label(self, key: str) -> str:
        return key.replace("_", " ").title()

    def _detail_navigation_target(self, event: dict, detail: dict, key: str, text: str):
        path = detail.get("source_path")
        if not path and isinstance(event.get("target"), str) and str(event.get("target")).startswith("/"):
            path = event.get("target")
        if key == "source_path" and isinstance(path, str) and path.startswith("/"):
            return (path, 0)
        if "offset" in key.lower() and isinstance(path, str) and path.startswith("/"):
            try:
                offset = int(str(text), 0)
            except ValueError:
                return None
            return (path, offset)
        return None

    def _reset_histogram_scroll(self) -> None:
        self.histogram_scroll.horizontalScrollBar().setValue(0)


class TimelineDialog(QDialog):

    def __init__(self, events: list[dict], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Timeline")
        self.resize(1180, 760)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        explorer = TimelineExplorerWidget(events, self)
        layout.addWidget(explorer)


class ProgressDialog(QDialog):

    def __init__(self, title: str, total_steps: int = 0, parent=None):
        super().__init__(parent)
        self._total_steps = max(total_steps, 0)
        self._completed_steps = 0
        self._pulse_value = 10

        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedSize(QSize(420, 150))
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setStyleSheet("""
            QDialog {
                background: #ffffff;
                border: 1px solid #e1e5ea;
                border-radius: 10px;
            }
            QLabel {
                color: #1f2933;
            }
            QProgressBar {
                background: #eef2f7;
                border: 1px solid #d7dee7;
                border-radius: 7px;
                min-height: 14px;
                max-height: 14px;
                text-align: center;
                color: transparent;
            }
            QProgressBar::chunk {
                background: #2563eb;
                border-radius: 6px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("font-weight: 700; font-size: 14px;")
        layout.addWidget(self.title_label)

        self.message_label = QLabel("Starting...")
        self.message_label.setWordWrap(True)
        self.message_label.setMinimumHeight(34)
        self.message_label.setStyleSheet("color: #6b7280;")
        layout.addWidget(self.message_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        layout.addWidget(self.progress_bar)

        self.percent_label = QLabel("0%")
        self.percent_label.setAlignment(Qt.AlignRight)
        self.percent_label.setStyleSheet("color: #2563eb; font-weight: 600;")
        layout.addWidget(self.percent_label)

    def set_message(self, message: str) -> None:
        self.message_label.setText(message)

    def set_progress(self, value: int) -> None:
        value = max(0, min(100, value))
        self.progress_bar.setValue(value)
        self.percent_label.setText(f"{value}%")

    def update_from_log(self, message: str) -> None:
        if "building timeline from" in message and self._total_steps:
            self.set_message("Collecting timeline events...")
            self._completed_steps += 1
            value = 5 + int((self._completed_steps / self._total_steps) * 85)
            self.set_progress(value)
            return

        if "[ERROR]" in message:
            self.set_message("An error occurred while processing.")
            return

        self.set_message("Collecting and parsing...")
        self._pulse_value = min(92, self._pulse_value + 8)
        self.set_progress(self._pulse_value)

    def complete(self, message: str = "Completed") -> None:
        self.set_message(message)
        self.set_progress(100)
