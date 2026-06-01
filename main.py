import os
import sys
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout
from ui import CaseWindow, MainWindow


class ModeSelectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Start Mode")
        self.setModal(True)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setMinimumWidth(420)
        self.selected_mode = "classic"
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        title = QLabel("Choose startup mode")
        title.setStyleSheet("font-size: 13pt; font-weight: 700;")
        hint = QLabel("Classic mode keeps the existing workflow. Case Flow mode starts the case-first workflow.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #64748b;")
        layout.addWidget(title)
        layout.addWidget(hint)

        row = QHBoxLayout()
        classic_btn = QPushButton("Classic")
        flow_btn = QPushButton("Case Flow")
        classic_btn.setMinimumHeight(34)
        flow_btn.setMinimumHeight(34)
        classic_btn.clicked.connect(self._select_classic)
        flow_btn.clicked.connect(self._select_flow)
        row.addWidget(classic_btn)
        row.addWidget(flow_btn)
        layout.addLayout(row)

    def _select_classic(self):
        self.selected_mode = "classic"
        self.accept()

    def _select_flow(self):
        self.selected_mode = "caseflow"
        self.accept()

def main():
    app = QApplication(sys.argv)
    icon_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Icon.png"))
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    window = CaseWindow()
    window.showMaximized()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
