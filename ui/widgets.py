import os

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)
from PyQt5.QtGui import QKeySequence


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
        self.setWindowTitle("Start")
        self.setModal(True)
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        button_row = QHBoxLayout()
        open_btn = QPushButton("New File")
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