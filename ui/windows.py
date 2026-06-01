import html
import json
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QIcon
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QAction,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStatusBar,
    QStackedWidget,
    QTabWidget,
    QTextEdit,
    QTableWidgetItem,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from image_handler import ImageHandler
from collectors.artifact_utils import WINDOWS_ROOT_CANDIDATES, first_existing_dir, iter_user_directories
from .constants import (
    ARTIFACT_INDEX,
    ARTIFACT_REGISTRY,
    ARTIFACT_RUNNERS,
    C_AMBER,
    C_BG,
    C_BLUE,
    C_BORDER,
    C_GREEN,
    C_HEADER,
    C_PANEL,
    C_RED,
    C_SELECT,
    C_SUBTEXT,
    C_TEXT,
    build_timeline_entries,
)
from .widgets import CopyableTableWidget, ProgressDialog, TimelineExplorerWidget

UI_FONT_FAMILY = "Malgun Gothic"


@dataclass
class CaseConfig:
    case_number: str
    case_name: str
    investigator: str
    image_path: str
    partition_offsets: list[int]
    artifact_ids: list[str]
    case_storage_dir: str = ""
    case_output_name: str = ""
    case_output_dir: str = ""


def _default_case_storage_dir() -> str:
    return os.path.join(os.path.expanduser("~"), "Documents", "Insider Cases")


def _slugify_case_name(case_name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {" ", "-", "_"} else "_" for ch in (case_name or "Untitled Case"))
    compact = "_".join(cleaned.strip().split())
    return compact or "Untitled_Case"


def _sanitize_for_json(value):
    if isinstance(value, datetime):
        ts = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).isoformat()
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, dict):
        blocked = {"file_object", "_fs", "_local_path", "_temp_path", "tmp_path", "temp_path"}
        return {
            str(k): _sanitize_for_json(v)
            for k, v in value.items()
            if k not in blocked
        }
    if isinstance(value, list):
        return [_sanitize_for_json(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_for_json(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _persist_case_bundle(case_config: CaseConfig, artifact_cache: dict, timeline: list[dict], risk_result: dict) -> str:
    storage_root = case_config.case_storage_dir or _default_case_storage_dir()
    os.makedirs(storage_root, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_name = case_config.case_output_name or case_config.case_name
    case_dir = os.path.join(storage_root, f"{_slugify_case_name(output_name)}_{timestamp}")
    os.makedirs(case_dir, exist_ok=False)
    os.makedirs(os.path.join(case_dir, "artifacts"), exist_ok=True)

    case_json = {
        "case_number": case_config.case_number,
        "case_name": case_config.case_name,
        "investigator": case_config.investigator,
        "image_path": case_config.image_path,
        "case_output_name": case_config.case_output_name,
        "selected_partitions": case_config.partition_offsets,
        "selected_artifacts": case_config.artifact_ids,
        "stored_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as stream:
        json.dump(case_json, stream, ensure_ascii=False, indent=2)

    with open(os.path.join(case_dir, "timeline.json"), "w", encoding="utf-8") as stream:
        json.dump(_sanitize_for_json(timeline), stream, ensure_ascii=False, indent=2)

    with open(os.path.join(case_dir, "risk_result.json"), "w", encoding="utf-8") as stream:
        json.dump(_sanitize_for_json(risk_result), stream, ensure_ascii=False, indent=2)

    for artifact_id, entries in artifact_cache.items():
        out_path = os.path.join(case_dir, "artifacts", f"{artifact_id}.json")
        with open(out_path, "w", encoding="utf-8") as stream:
            json.dump(_sanitize_for_json(entries), stream, ensure_ascii=False, indent=2)

    return case_dir


class CaseIntakeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("사건 생성")
        self.setModal(True)
        self.setMinimumSize(760, 720)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self._artifact_checks: dict[str, QCheckBox] = {}
        self._build_ui()
        self._apply_style()
        self._apply_fonts()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        title = QLabel("Create Case")
        title.setObjectName("title")
        subtitle = QLabel(
            "Enter case information, choose a forensic image, and select the artifacts to include in the first-pass analysis."
        )
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        details_box = QGroupBox("Case Information")
        details_form = QFormLayout(details_box)
        details_form.setLabelAlignment(Qt.AlignRight)
        self.case_number_edit = QLineEdit()
        self.case_name_edit = QLineEdit()
        self.investigator_edit = QLineEdit()
        self.case_number_edit.setPlaceholderText("CASE-2026-001")
        self.case_name_edit.setPlaceholderText("Employee data exfiltration review")
        self.investigator_edit.setPlaceholderText("Analyst name")
        details_form.addRow("Case Number", self.case_number_edit)
        details_form.addRow("Case Name", self.case_name_edit)
        details_form.addRow("Investigator", self.investigator_edit)
        layout.addWidget(details_box)

        storage_box = QGroupBox("Case Storage")
        storage_layout = QHBoxLayout(storage_box)
        self.case_storage_edit = QLineEdit()
        self.case_storage_edit.setText(_default_case_storage_dir())
        self.case_storage_edit.setPlaceholderText("Select a folder to store generated case files")
        storage_btn = QPushButton("Browse")
        storage_btn.clicked.connect(self._browse_storage_dir)
        storage_layout.addWidget(self.case_storage_edit, stretch=1)
        storage_layout.addWidget(storage_btn)
        layout.addWidget(storage_box)

        image_box = QGroupBox("Evidence Image")
        image_layout = QHBoxLayout(image_box)
        self.image_path_edit = QLineEdit()
        self.image_path_edit.setPlaceholderText("Select a forensic image file")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_image)
        image_layout.addWidget(self.image_path_edit, stretch=1)
        image_layout.addWidget(browse_btn)
        layout.addWidget(image_box)

        artifacts_box = QGroupBox("Artifacts To Analyze")
        artifacts_layout = QVBoxLayout(artifacts_box)
        help_label = QLabel(
            "Select the artifacts to parse for the initial case build. Timeline and risk analysis will use the selected artifacts."
        )
        help_label.setObjectName("hint")
        help_label.setWordWrap(True)
        artifacts_layout.addWidget(help_label)

        quick_row = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        clear_all_btn = QPushButton("Clear All")
        select_all_btn.clicked.connect(lambda: self._set_all_artifacts(True))
        clear_all_btn.clicked.connect(lambda: self._set_all_artifacts(False))
        quick_row.addWidget(select_all_btn)
        quick_row.addWidget(clear_all_btn)
        quick_row.addStretch(1)
        artifacts_layout.addLayout(quick_row)

        grid = QGridLayout()
        row = 0
        col = 0
        for artifact in ARTIFACT_REGISTRY:
            if artifact["id"] == "timeline":
                continue
            check = QCheckBox(artifact["label"])
            check.setChecked(True)
            check.setToolTip(artifact["description"])
            self._artifact_checks[artifact["id"]] = check
            grid.addWidget(check, row, col)
            col += 1
            if col == 2:
                col = 0
                row += 1
        artifacts_layout.addLayout(grid)
        layout.addWidget(artifacts_box, stretch=1)

        action_row = QHBoxLayout()
        action_row.addStretch(1)
        cancel_btn = QPushButton("Cancel")
        build_btn = QPushButton("Create And Analyze")
        cancel_btn.clicked.connect(self.reject)
        build_btn.clicked.connect(self._accept_if_valid)
        cancel_btn.setObjectName("secondary")
        build_btn.setObjectName("primary")
        action_row.addWidget(cancel_btn)
        action_row.addWidget(build_btn)
        layout.addLayout(action_row)

    def _apply_style(self) -> None:
        self.setStyleSheet(
            f"""
            QDialog {{
                background: {C_BG};
                color: {C_TEXT};
                font-family: 'Malgun Gothic', sans-serif;
                font-size: 10pt;
            }}
            QLabel#title {{
                font-size: 18pt;
                font-weight: 700;
                color: {C_TEXT};
            }}
            QLabel#subtitle, QLabel#hint {{
                color: {C_SUBTEXT};
            }}
            QGroupBox {{
                background: {C_PANEL};
                border: 1px solid {C_BORDER};
                border-radius: 10px;
                margin-top: 12px;
                padding-top: 12px;
                font-weight: 700;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 4px;
                color: {C_BLUE};
            }}
            QLineEdit, QTextEdit {{
                background: white;
                border: 1px solid {C_BORDER};
                border-radius: 8px;
                padding: 8px 10px;
            }}
            QPushButton {{
                min-height: 34px;
                border-radius: 8px;
                padding: 0 14px;
                font-weight: 600;
                border: 1px solid {C_BORDER};
                background: white;
                color: {C_TEXT};
            }}
            QPushButton:hover {{
                background: {C_SELECT};
                color: {C_BLUE};
            }}
            QPushButton#primary {{
                background: {C_BLUE};
                color: white;
                border: none;
            }}
            QPushButton#primary:hover {{
                background: #1d4ed8;
            }}
            QPushButton#secondary {{
                background: {C_HEADER};
                color: {C_TEXT};
            }}
            QCheckBox {{
                spacing: 8px;
                padding: 4px 0;
            }}
            """
        )

    def _apply_fonts(self) -> None:
        base_font = QFont(UI_FONT_FAMILY, 10)
        title_font = QFont(UI_FONT_FAMILY, 24)
        title_font.setWeight(QFont.DemiBold)
        self.setFont(base_font)
        for widget in self.findChildren((QLabel, QLineEdit, QPushButton, QCheckBox, QGroupBox)):
            widget.setFont(base_font)
        title = self.findChild(QLabel, "title")
        if title is not None:
            title.setFont(title_font)

    def _browse_image(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Image",
            "",
            "Disk Images (*.001 *.dd *.raw *.img);;EWF Images (*.E01 *.e01);;All Files (*)",
        )
        if path:
            self.image_path_edit.setText(path)

    def _browse_storage_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Case Storage Folder", self.case_storage_edit.text().strip() or _default_case_storage_dir())
        if path:
            self.case_storage_edit.setText(path)

    def _set_all_artifacts(self, checked: bool) -> None:
        for check in self._artifact_checks.values():
            check.setChecked(checked)

    def _accept_if_valid(self) -> None:
        image_path = self.image_path_edit.text().strip()
        storage_dir = self.case_storage_edit.text().strip()
        if not self.case_name_edit.text().strip():
            QMessageBox.warning(self, "사건명 누락", "계속하려면 사건명을 입력하세요.")
            return
        if not image_path or not os.path.exists(image_path):
            QMessageBox.warning(self, "이미지 누락", "유효한 포렌식 이미지를 선택하세요.")
            return
        if not storage_dir:
            QMessageBox.warning(self, "저장 경로 누락", "결과를 저장할 폴더를 선택하세요.")
            return
        try:
            os.makedirs(storage_dir, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(self, "저장 경로 오류", f"저장 폴더를 생성할 수 없습니다.\n{exc}")
            return
        if not self.selected_artifacts():
            QMessageBox.warning(self, "아티팩트 미선택", "최소 1개 이상의 아티팩트를 선택하세요.")
            return
        self.accept()

    def selected_artifacts(self) -> list[str]:
        return [artifact_id for artifact_id, check in self._artifact_checks.items() if check.isChecked()]

    def case_config(self) -> CaseConfig:
        return CaseConfig(
            case_number=self.case_number_edit.text().strip(),
            case_name=self.case_name_edit.text().strip(),
            investigator=self.investigator_edit.text().strip(),
            image_path=self.image_path_edit.text().strip(),
            partition_offsets=[],
            artifact_ids=self.selected_artifacts(),
            case_storage_dir=self.case_storage_edit.text().strip(),
            case_output_name=self.case_name_edit.text().strip(),
        )


class StartPageWidget(QWidget):
    new_case_requested = pyqtSignal()
    open_case_requested = pyqtSignal()
    open_recent_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        layout.addStretch(1)

        title = QLabel("insider_exfil_tool")
        title.setObjectName("title")
        subtitle = QLabel("새 사건을 생성하거나 최근 사건을 다시 열 수 있습니다.")
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        subtitle.setAlignment(Qt.AlignCenter)

        button_row = QHBoxLayout()
        button_row.setSpacing(16)
        self.new_case_btn = QPushButton("새 사건")
        self.new_case_btn.setObjectName("primary")
        self.new_case_btn.setMinimumWidth(180)
        self.open_case_btn = QPushButton("사건 열기")
        self.open_case_btn.setObjectName("secondary")
        self.open_case_btn.setMinimumWidth(180)
        self.new_case_btn.clicked.connect(self.new_case_requested.emit)
        self.open_case_btn.clicked.connect(self.open_case_requested.emit)
        button_row.addStretch(1)
        button_row.addWidget(self.new_case_btn)
        button_row.addWidget(self.open_case_btn)
        button_row.addStretch(1)

        layout.addWidget(title, alignment=Qt.AlignCenter)
        layout.addWidget(subtitle)
        layout.addLayout(button_row)

        recent_label = QLabel("최근 사건")
        recent_label.setObjectName("subtitle")
        recent_label.setAlignment(Qt.AlignCenter)
        self.recent_list = QListWidget()
        self.recent_list.setMaximumHeight(220)
        self.recent_list.setFixedWidth(1200)
        self.recent_list.itemDoubleClicked.connect(self._on_recent_double_clicked)
        layout.addWidget(recent_label)
        layout.addWidget(self.recent_list, alignment=Qt.AlignHCenter)
        layout.addStretch(2)

        self.setStyleSheet(
            f"""
            QWidget {{
                background: {C_BG};
                color: {C_TEXT};
                font-family: 'Malgun Gothic', sans-serif;
            }}
            QLabel#title {{
                font-size: 28pt;
                font-weight: 700;
            }}
            QLabel#subtitle {{
                color: {C_SUBTEXT};
                font-size: 11pt;
            }}
            QPushButton {{
                min-height: 44px;
                border-radius: 10px;
                padding: 0 18px;
                font-weight: 700;
                border: 1px solid {C_BORDER};
                background: white;
                color: {C_TEXT};
            }}
            QPushButton:hover {{
                background: {C_SELECT};
                color: {C_BLUE};
            }}
            QPushButton#primary {{
                background: {C_BLUE};
                border: none;
                color: white;
            }}
            QPushButton#primary:hover {{
                background: #1d4ed8;
            }}
            QPushButton#secondary {{
                background: {C_PANEL};
                color: {C_TEXT};
            }}
            """
        )

    def set_recent_cases(self, cases: list[dict]) -> None:
        self.recent_list.clear()
        for case in cases:
            display = case.get("display_name") or "이름 없는 사건"
            path = case.get("case_dir") or ""
            item = QListWidgetItem(f"{display}\n{path}")
            item.setData(Qt.UserRole, path)
            self.recent_list.addItem(item)

    def selected_recent_case_path(self) -> str:
        item = self.recent_list.currentItem()
        if item is None:
            return ""
        return str(item.data(Qt.UserRole) or "")

    def _on_recent_double_clicked(self, item: QListWidgetItem) -> None:
        path = str(item.data(Qt.UserRole) or "")
        if path:
            self.open_recent_requested.emit(path)


class ImagePreviewWorker(QThread):
    done = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, image_path: str):
        super().__init__()
        self.image_path = image_path

    def run(self) -> None:
        try:
            handler = ImageHandler()
            handler.open(self.image_path)
            if not handler.volumes:
                self.error.emit("[ERROR] no readable volume found")
                return

            previews = []
            for volume in handler.volumes:
                fs = volume.get("fs")
                artifact_status = self._detect_artifacts(handler, fs)
                previews.append(
                    {
                        "offset": int(volume.get("offset", 0)),
                        "desc": volume.get("desc", "Unknown Volume"),
                        "artifact_status": artifact_status,
                    }
                )
            handler.close()
            self.done.emit({"image_path": self.image_path, "volumes": previews})
        except Exception as exc:
            self.error.emit(f"[ERROR] image preview failed: {exc}")

    def _detect_artifacts(self, handler: ImageHandler, fs) -> dict:
        def path_exists(path: str, directory: bool = True) -> bool:
            try:
                if directory:
                    fs.open_dir(path=path)
                else:
                    fs.open(path=path)
                return True
            except Exception:
                return False

        def user_path_exists(relative_path: str, directory: bool = True) -> bool:
            for user in user_dirs:
                candidate = f"{user['path'].rstrip('/')}/{relative_path}"
                if path_exists(candidate, directory=directory):
                    return True
            return False

        windows_root = first_existing_dir(handler, fs, WINDOWS_ROOT_CANDIDATES)
        user_dirs = iter_user_directories(handler, fs)
        ntusers = handler.find_ntuser_dat(fs)
        has_users = bool(user_dirs)
        has_event_logs = bool(windows_root and path_exists(f"{windows_root}/System32/winevt/Logs"))
        has_prefetch = bool(windows_root and path_exists(f"{windows_root}/Prefetch"))
        has_spool = bool(windows_root and path_exists(f"{windows_root}/System32/spool/PRINTERS"))
        has_system_hive = bool(windows_root and path_exists(f"{windows_root}/System32/config/SYSTEM", directory=False))
        has_amcache = (
            bool(windows_root and path_exists(f"{windows_root}/appcompat/Programs/Amcache.hve", directory=False))
            or bool(windows_root and path_exists(f"{windows_root}/AppCompat/Programs/Amcache.hve", directory=False))
        )

        has_browser = any(
            (
                user_path_exists("AppData/Local/Google/Chrome/User Data"),
                user_path_exists("AppData/Local/Microsoft/Edge/User Data"),
                user_path_exists("AppData/Roaming/Mozilla/Firefox/Profiles"),
            )
        )

        has_lnk = any(
            (
                user_path_exists("AppData/Roaming/Microsoft/Windows/Recent"),
                user_path_exists("Desktop"),
                user_path_exists("AppData/Roaming/Microsoft/Windows/Start Menu"),
            )
        )

        has_jumplist = any(
            (
                user_path_exists("AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations"),
                user_path_exists("AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations"),
            )
        )

        has_ntuser_hives = bool(ntusers)

        has_outlook = False
        if user_dirs:
            try:
                for user_dir in user_dirs:
                    for outlook_path in (
                        f"{user_dir['path']}/AppData/Local/Microsoft/Outlook",
                        f"{user_dir['path']}/Documents/Outlook Files",
                    ):
                        if path_exists(outlook_path):
                            has_outlook = True
                            break
                    if has_outlook:
                        break
            except Exception:
                has_outlook = False

        status = {
            "filesystem": True,
            "lnk": has_lnk,
            "eventlog": has_event_logs,
            "recentdocs": has_ntuser_hives,
            "browser_artifacts": has_browser,
            "userassist": has_ntuser_hives,
            "jumplist": has_jumplist,
            "shellbags": has_ntuser_hives,
            "mounteddevices": has_system_hive,
            "usb": has_system_hive,
            "spool": has_spool,
            "prefetch": has_prefetch,
            "amcache": has_amcache,
            "ost_pst": has_outlook,
        }
        return status


class CaseIntakeWidget(QWidget):
    start_requested = pyqtSignal(object)
    image_preview_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._artifact_checks: dict[str, QCheckBox] = {}
        self._artifact_state_labels: dict[str, QLabel] = {}
        self._partition_checks: dict[int, QCheckBox] = {}
        self._preview_data: Optional[dict] = None
        self._build_ui()
        self._apply_style()
        self._apply_fonts()

    def _build_ui(self) -> None:
        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        shell.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)

        outer = QVBoxLayout(content)
        outer.setContentsMargins(24, 18, 24, 24)
        outer.setSpacing(18)
        outer.setAlignment(Qt.AlignTop)

        title = QLabel("Create Case")
        title.setObjectName("title")
        subtitle = QLabel("Enter case information, load an evidence image, choose partitions, and then select detected artifacts.")
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        outer.addWidget(title)
        outer.addWidget(subtitle)

        details_box = QGroupBox("Case Information")
        details_form = QFormLayout(details_box)
        details_form.setLabelAlignment(Qt.AlignRight)
        self.case_number_edit = QLineEdit()
        self.case_name_edit = QLineEdit()
        self.investigator_edit = QLineEdit()
        self.case_number_edit.setPlaceholderText("Optional")
        self.case_name_edit.setPlaceholderText("Optional")
        self.investigator_edit.setPlaceholderText("Optional")
        details_form.addRow("Case Number", self.case_number_edit)
        details_form.addRow("Case Name", self.case_name_edit)
        details_form.addRow("Investigator", self.investigator_edit)
        outer.addWidget(details_box)

        storage_box = QGroupBox("Case Output")
        storage_layout = QHBoxLayout(storage_box)
        self.case_storage_edit = QLineEdit()
        self.case_storage_edit.setText(_default_case_storage_dir())
        self.case_storage_edit.setPlaceholderText("Select a folder to save the generated case package")
        self.case_output_name_edit = QLineEdit()
        self.case_output_name_edit.setPlaceholderText("Required result folder name")
        storage_btn = QPushButton("Browse")
        storage_btn.clicked.connect(self._browse_storage_dir)
        storage_form = QFormLayout()
        storage_form.setLabelAlignment(Qt.AlignRight)
        storage_row = QHBoxLayout()
        storage_row.addWidget(self.case_storage_edit, stretch=1)
        storage_row.addWidget(storage_btn)
        storage_form.addRow("Save Folder", storage_row)
        storage_form.addRow("Result Name", self.case_output_name_edit)
        storage_layout.addLayout(storage_form)
        outer.addWidget(storage_box)

        image_box = QGroupBox("Evidence Image")
        image_layout = QHBoxLayout(image_box)
        self.image_path_edit = QLineEdit()
        self.image_path_edit.setPlaceholderText("Select a forensic image file")
        browse_btn = QPushButton("Browse")
        inspect_btn = QPushButton("Scan Image")
        inspect_btn.setObjectName("primary")
        browse_btn.clicked.connect(self._browse_image)
        inspect_btn.clicked.connect(self._request_image_preview)
        image_layout.addWidget(self.image_path_edit, stretch=1)
        image_layout.addWidget(browse_btn)
        image_layout.addWidget(inspect_btn)
        outer.addWidget(image_box)

        self.partition_box = QGroupBox("Partitions To Analyze")
        partition_layout = QVBoxLayout(self.partition_box)
        self.partition_hint = QLabel("Load an image to review readable partitions.")
        self.partition_hint.setObjectName("hint")
        self.partition_hint.setWordWrap(True)
        partition_layout.addWidget(self.partition_hint)
        self.partition_grid = QGridLayout()
        self.partition_grid.setHorizontalSpacing(18)
        self.partition_grid.setVerticalSpacing(10)
        partition_layout.addLayout(self.partition_grid)
        self.partition_box.setVisible(False)
        outer.addWidget(self.partition_box)

        self.artifacts_box = QGroupBox("Artifacts To Analyze")
        artifacts_layout = QVBoxLayout(self.artifacts_box)
        self.artifact_hint = QLabel("Choose from artifacts detected on the selected partitions.")
        self.artifact_hint.setObjectName("hint")
        self.artifact_hint.setWordWrap(True)
        artifacts_layout.addWidget(self.artifact_hint)

        quick_row = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        clear_all_btn = QPushButton("Clear All")
        select_all_btn.clicked.connect(lambda: self._set_all_artifacts(True))
        clear_all_btn.clicked.connect(lambda: self._set_all_artifacts(False))
        quick_row.addWidget(select_all_btn)
        quick_row.addWidget(clear_all_btn)
        quick_row.addStretch(1)
        artifacts_layout.addLayout(quick_row)

        artifact_grid = QGridLayout()
        artifact_grid.setHorizontalSpacing(18)
        artifact_grid.setVerticalSpacing(10)
        row = 0
        col = 0
        for artifact in ARTIFACT_REGISTRY:
            if artifact["id"] == "timeline":
                continue
            item_box = QWidget()
            item_layout = QVBoxLayout(item_box)
            item_layout.setContentsMargins(10, 8, 10, 8)
            item_layout.setSpacing(4)
            check = QCheckBox(artifact["label"])
            check.setChecked(True)
            check.setEnabled(False)
            check.setToolTip(artifact["description"])
            check.toggled.connect(lambda _checked, self=self: self.build_btn.setEnabled(bool(self.selected_artifacts())))
            state = QLabel("Not scanned yet")
            state.setObjectName("artifact_state")
            self._artifact_checks[artifact["id"]] = check
            self._artifact_state_labels[artifact["id"]] = state
            item_layout.addWidget(check)
            item_layout.addWidget(state)
            artifact_grid.addWidget(item_box, row, col)
            col += 1
            if col == 2:
                col = 0
                row += 1
        artifacts_layout.addLayout(artifact_grid)
        self.artifacts_box.setVisible(False)
        outer.addWidget(self.artifacts_box)

        action_row = QHBoxLayout()
        action_row.addStretch(1)
        self.build_btn = QPushButton("Create And Analyze")
        self.build_btn.setObjectName("primary")
        self.build_btn.setEnabled(False)
        self.build_btn.setVisible(False)
        self.build_btn.clicked.connect(self._submit_if_valid)
        action_row.addWidget(self.build_btn)
        outer.addLayout(action_row)
        outer.addStretch(1)

    def _apply_style(self) -> None:
        self.setStyleSheet(
            f"""
            QWidget {{
                background: {C_BG};
                color: {C_TEXT};
                font-family: 'Malgun Gothic', sans-serif;
                font-size: 10pt;
            }}
            QLabel {{
                background: transparent;
            }}
            QLabel#title {{
                font-size: 24pt;
                font-weight: 700;
                color: {C_TEXT};
            }}
            QLabel#subtitle, QLabel#hint, QLabel#artifact_state {{
                color: {C_SUBTEXT};
            }}
            QGroupBox {{
                background: {C_PANEL};
                border: 1px solid {C_BORDER};
                border-radius: 10px;
                margin-top: 12px;
                padding-top: 12px;
                font-weight: 700;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 4px;
                color: {C_BLUE};
            }}
            QLineEdit {{
                background: white;
                border: 1px solid {C_BORDER};
                border-radius: 8px;
                padding: 8px 10px;
            }}
            QPushButton {{
                min-height: 34px;
                border-radius: 8px;
                padding: 0 14px;
                font-weight: 600;
                border: 1px solid {C_BORDER};
                background: white;
                color: {C_TEXT};
            }}
            QPushButton:hover {{
                background: {C_SELECT};
                color: {C_BLUE};
            }}
            QPushButton#primary {{
                background: {C_BLUE};
                color: white;
                border: none;
            }}
            QPushButton#primary:hover {{
                background: #1d4ed8;
            }}
            QCheckBox {{
                spacing: 8px;
                padding: 2px 0;
                font-weight: 600;
            }}
            """
        )

    def _apply_fonts(self) -> None:
        base_font = QFont(UI_FONT_FAMILY, 10)
        title_font = QFont(UI_FONT_FAMILY, 24)
        title_font.setWeight(QFont.DemiBold)
        self.setFont(base_font)
        for widget in self.findChildren((QLabel, QLineEdit, QPushButton, QCheckBox, QGroupBox)):
            widget.setFont(base_font)
        title = self.findChild(QLabel, "title")
        if title is not None:
            title.setFont(title_font)

    def reset(self) -> None:
        self.case_number_edit.clear()
        self.case_name_edit.clear()
        self.investigator_edit.clear()
        self.case_storage_edit.setText(_default_case_storage_dir())
        self.case_output_name_edit.clear()
        self.image_path_edit.clear()
        self._preview_data = None
        self.partition_box.setVisible(False)
        self.artifacts_box.setVisible(False)
        self.build_btn.setVisible(False)
        self.partition_hint.setText("Load an image to review readable partitions.")
        self._clear_partition_grid()
        for artifact_id, check in self._artifact_checks.items():
            check.setChecked(True)
            check.setEnabled(False)
            self._artifact_state_labels[artifact_id].setText("Not scanned yet")
        self.build_btn.setEnabled(False)

    def _browse_image(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Image",
            "",
            "Disk Images (*.001 *.dd *.raw *.img);;EWF Images (*.E01 *.e01);;All Files (*)",
        )
        if path:
            self.image_path_edit.setText(path)

    def _browse_storage_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self,
            "Select Case Storage Folder",
            self.case_storage_edit.text().strip() or _default_case_storage_dir(),
        )
        if path:
            self.case_storage_edit.setText(path)

    def _request_image_preview(self) -> None:
        image_path = self.image_path_edit.text().strip()
        if not image_path or not os.path.exists(image_path):
            QMessageBox.warning(self, "이미지 누락", "유효한 포렌식 이미지를 선택하세요.")
            return
        self._preview_data = None
        self._clear_partition_grid()
        self._partition_checks.clear()
        for artifact_id, check in self._artifact_checks.items():
            check.setEnabled(False)
            check.setChecked(False)
            self._artifact_state_labels[artifact_id].setText("Scanning...")
        self.partition_box.setVisible(True)
        self.partition_hint.setText("Scanning partitions and detecting candidate artifacts...")
        self.artifacts_box.setVisible(False)
        self.build_btn.setEnabled(False)
        self.image_preview_requested.emit(image_path)

    def set_preview_result(self, preview_data: dict) -> None:
        self._preview_data = preview_data
        self.partition_box.setVisible(True)
        self.artifacts_box.setVisible(True)
        self.build_btn.setVisible(True)
        self._clear_partition_grid()
        self._partition_checks.clear()
        volumes = preview_data.get("volumes", [])
        self.partition_hint.setText(f"Detected {len(volumes)} readable partition(s). Select the partitions to analyze.")
        row = 0
        for volume in volumes:
            offset = int(volume.get("offset", 0))
            desc = volume.get("desc", "Unknown Volume")
            check = QCheckBox(desc)
            check.setChecked(True)
            check.stateChanged.connect(lambda _state, self=self: self._refresh_artifact_states())
            details = QLabel(f"Offset: {offset}")
            details.setObjectName("artifact_state")
            self._partition_checks[offset] = check
            self.partition_grid.addWidget(check, row, 0)
            self.partition_grid.addWidget(details, row, 1)
            row += 1
        self._refresh_artifact_states()

    def _clear_partition_grid(self) -> None:
        while self.partition_grid.count():
            item = self.partition_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _refresh_artifact_states(self) -> None:
        selected_offsets = set(self.selected_partition_offsets())
        if not self._preview_data or not selected_offsets:
            for artifact_id, check in self._artifact_checks.items():
                check.setEnabled(False)
                self._artifact_state_labels[artifact_id].setText("Select at least one partition")
            self.build_btn.setEnabled(False)
            return

        volume_statuses = {
            int(volume.get("offset", 0)): volume.get("artifact_status", {})
            for volume in self._preview_data.get("volumes", [])
        }
        for artifact_id, check in self._artifact_checks.items():
            detected = any(volume_statuses.get(offset, {}).get(artifact_id, False) for offset in selected_offsets)
            check.setEnabled(detected)
            if not detected:
                check.setChecked(False)
            elif not check.isChecked():
                check.setChecked(True)
            self._artifact_state_labels[artifact_id].setText("Detected" if detected else "Not detected on selected partitions")
        self.build_btn.setEnabled(bool(self.selected_artifacts()))

    def _set_all_artifacts(self, checked: bool) -> None:
        for check in self._artifact_checks.values():
            if check.isEnabled():
                check.setChecked(checked)
        self.build_btn.setEnabled(bool(self.selected_artifacts()))

    def selected_partition_offsets(self) -> list[int]:
        return [offset for offset, check in self._partition_checks.items() if check.isChecked()]

    def selected_artifacts(self) -> list[str]:
        return [artifact_id for artifact_id, check in self._artifact_checks.items() if check.isChecked() and check.isEnabled()]

    def case_config(self) -> CaseConfig:
        return CaseConfig(
            case_number=self.case_number_edit.text().strip(),
            case_name=self.case_name_edit.text().strip(),
            investigator=self.investigator_edit.text().strip(),
            image_path=self.image_path_edit.text().strip(),
            partition_offsets=self.selected_partition_offsets(),
            artifact_ids=self.selected_artifacts(),
            case_storage_dir=self.case_storage_edit.text().strip(),
            case_output_name=self.case_output_name_edit.text().strip(),
        )

    def _submit_if_valid(self) -> None:
        image_path = self.image_path_edit.text().strip()
        storage_dir = self.case_storage_edit.text().strip()
        output_name = self.case_output_name_edit.text().strip()
        if not output_name:
            QMessageBox.warning(self, "결과 이름 누락", "분석 시작 전에 결과 이름을 입력하세요.")
            return
        if not image_path or not os.path.exists(image_path):
            QMessageBox.warning(self, "이미지 누락", "유효한 포렌식 이미지를 선택하세요.")
            return
        if not storage_dir:
            QMessageBox.warning(self, "저장 경로 누락", "결과를 저장할 폴더를 선택하세요.")
            return
        try:
            os.makedirs(storage_dir, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(self, "저장 경로 오류", f"저장 폴더를 생성할 수 없습니다.\n{exc}")
            return
        if not self.selected_partition_offsets():
            QMessageBox.warning(self, "파티션 미선택", "최소 1개 이상의 파티션을 선택하세요.")
            return
        if not self.selected_artifacts():
            QMessageBox.warning(self, "아티팩트 미선택", "탐지된 아티팩트 중 최소 1개 이상 선택하세요.")
            return
        self.start_requested.emit(self.case_config())


class CaseBuildWorker(QThread):
    log_msg = pyqtSignal(str)
    error = pyqtSignal(str)
    done = pyqtSignal(object)
    progress = pyqtSignal(int, str)

    def __init__(self, case_config: CaseConfig):
        super().__init__()
        self.case_config = case_config

    def run(self) -> None:
        try:
            handler = ImageHandler()
            self.progress.emit(5, "Opening forensic image...")
            handler.open(self.case_config.image_path)
            if not handler.volumes:
                self.error.emit("[ERROR] no readable volume found")
                return
            if self.case_config.partition_offsets:
                selected = set(self.case_config.partition_offsets)
                handler.volumes = [
                    volume for volume in handler.volumes
                    if int(volume.get("offset", 0)) in selected
                ]
            if not handler.volumes:
                self.error.emit("[ERROR] no selected partition could be opened")
                return

            artifact_cache = {}
            total = max(1, len(self.case_config.artifact_ids) + 2)
            step = 1

            for artifact_id in self.case_config.artifact_ids:
                runner = ARTIFACT_RUNNERS.get(artifact_id)
                if runner is None:
                    continue
                self.progress.emit(int((step / total) * 100), f"Parsing {ARTIFACT_INDEX[artifact_id]['label']}...")
                self.log_msg.emit(f"[INFO] parsing artifact: {artifact_id}")
                artifact_cache[artifact_id] = runner(handler, self.log_msg.emit)
                step += 1

            self.progress.emit(int((step / total) * 100), "Building integrated timeline...")
            timeline = build_timeline_entries(handler, self.log_msg.emit, artifact_cache)
            step += 1

            self.progress.emit(int((step / total) * 100), "Calculating risk signals...")
            risk_result = evaluate_risk_patterns(artifact_cache, timeline)

            self.progress.emit(96, "Saving case package...")
            case_output_dir = _persist_case_bundle(self.case_config, artifact_cache, timeline, risk_result)
            self.case_config.case_output_dir = case_output_dir

            self.progress.emit(100, "사건 분석이 완료되었습니다.")
            self.done.emit(
                {
                    "handler": handler,
                    "artifact_cache": artifact_cache,
                    "timeline": timeline,
                    "risk_result": risk_result,
                    "case_config": self.case_config,
                    "case_output_dir": case_output_dir,
                }
            )
        except Exception as exc:
            self.error.emit(f"[ERROR] case build failed: {exc}")


RISK_RULES = [
    {
        "id": "mass_file_access",
        "name": "대량 파일 접근",
        "severity": "심각",
        "score": 25,
        "threshold": "60분 이내 파일 접근 30건 이상",
    },
    {
        "id": "usb_then_file_activity",
        "name": "USB 연결 후 파일 활동",
        "severity": "심각",
        "score": 22,
        "threshold": "USB 연결 후 10분 이내 파일 이벤트 5건 이상",
    },
    {
        "id": "night_activity",
        "name": "야간 시간대 활동 증가",
        "severity": "높음",
        "score": 15,
        "threshold": "22:00~06:00 이벤트 10건 이상",
    },
    {
        "id": "cloud_access",
        "name": "클라우드 서비스 접근",
        "severity": "심각",
        "score": 20,
        "threshold": "Dropbox/Google Drive/OneDrive/Box/Mega 접근 기록",
    },
    {
        "id": "archive_created",
        "name": "압축 파일 생성",
        "severity": "높음",
        "score": 12,
        "threshold": ".zip/.rar/.7z 생성 흔적",
    },
    {
        "id": "large_mail_attachment",
        "name": "대용량 첨부파일 발송",
        "severity": "높음",
        "score": 16,
        "threshold": "메일 첨부 5MB 이상 발송 흔적",
    },
    {
        "id": "suspicious_tool",
        "name": "의심 도구 실행",
        "severity": "심각",
        "score": 25,
        "threshold": "FileZilla 또는 rclone 실행 흔적",
    },
    {
        "id": "print_then_usb",
        "name": "인쇄 후 USB 연결",
        "severity": "심각",
        "score": 14,
        "threshold": "인쇄 후 30분 이내 USB 연결",
    },
    {
        "id": "delete_before_usb",
        "name": "USB 연결 직전 삭제 활동",
        "severity": "심각",
        "score": 18,
        "threshold": "USB 연결 1시간 이내 삭제/휴지통 이동 활동",
    },
    {
        "id": "repeated_logon_failure",
        "name": "반복 로그인 실패",
        "severity": "높음",
        "score": 16,
        "threshold": "10분 내 Event ID 4625 기록 5건 이상",
    },
    {
        "id": "new_storage_device",
        "name": "신규 저장장치 최초 사용",
        "severity": "심각",
        "score": 18,
        "threshold": "최초 설치/최초 식별 USB 장치 사용 흔적",
    },
]


def _event_is_night(timestamp: Optional[datetime]) -> bool:
    if not timestamp:
        return False
    ts = timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    hour = ts.astimezone(timezone.utc).hour
    return hour >= 22 or hour < 6


def _bytes_to_mb(size_value) -> float:
    try:
        return float(size_value) / (1024 * 1024)
    except Exception:
        return 0.0


def _format_event_brief(event: dict) -> str:
    ts = event.get("timestamp")
    if ts and getattr(ts, "tzinfo", None) is None:
        ts = ts.replace(tzinfo=timezone.utc)
    when = ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "Unknown time"
    target = event.get("target") or event.get("summary") or event.get("action") or ""
    return f"{when} | {target}"


def _format_entry_brief(entry: dict) -> str:
    parts = []
    path = entry.get("source_path") or entry.get("entry_name") or ""
    if path:
        parts.append(str(path))
    size = entry.get("size")
    if size is not None:
        parts.append(f"size={size}")
    return " | ".join(parts) if parts else json.dumps(entry, ensure_ascii=False, default=str)


def _add_rule_finding(findings: list, rule_id: str, detail: str, evidence_lines: list[str]) -> int:
    rule = next(rule for rule in RISK_RULES if rule["id"] == rule_id)
    findings.append(
        {
            "rule_id": rule["id"],
            "name": rule["name"],
            "severity": rule["severity"],
            "score": rule["score"],
            "threshold": rule["threshold"],
            "detail": detail,
            "evidence_lines": evidence_lines,
        }
    )
    return rule["score"]


def evaluate_risk_patterns(artifact_cache: dict, timeline: list[dict]) -> dict:
    findings = []
    score = 0

    filesystem_events = [e for e in timeline if e.get("artifact_type") == "filesystem"]
    usb_events = [e for e in timeline if e.get("artifact_type") == "usb"]
    web_events = [e for e in timeline if e.get("artifact_type") == "browser_artifacts"]
    mail_events = [e for e in timeline if e.get("artifact_type") == "ost_pst"]
    exec_events = [e for e in timeline if e.get("artifact_type") in {"prefetch", "amcache", "userassist"}]
    eventlog_entries = artifact_cache.get("eventlog", [])
    filesystem_entries = artifact_cache.get("filesystem", [])

    # 1. Mass file access
    for pivot in filesystem_events:
        ts = pivot.get("timestamp")
        if not ts:
            continue
        window_end = ts + timedelta(minutes=60)
        window_events = [e for e in filesystem_events if e.get("timestamp") and ts <= e["timestamp"] <= window_end]
        count = len(window_events)
        if count >= 30:
            score += _add_rule_finding(
                findings,
                "mass_file_access",
                f"{count} file access events were recorded within 60 minutes.",
                [_format_event_brief(event) for event in window_events[:5]],
            )
            break

    # 2. USB connected then file creation/copy activity
    for usb in usb_events:
        ts = usb.get("timestamp")
        if not ts:
            continue
        window_end = ts + timedelta(minutes=10)
        window_events = [e for e in filesystem_events if e.get("timestamp") and ts <= e["timestamp"] <= window_end]
        count = len(window_events)
        if count >= 5:
            evidence = [_format_event_brief(usb)] + [_format_event_brief(event) for event in window_events[:4]]
            score += _add_rule_finding(
                findings,
                "usb_then_file_activity",
                f"{count} filesystem events occurred within 10 minutes of USB activity.",
                evidence,
            )
            break

    # 3. Night activity
    night_events = [e for e in timeline if _event_is_night(e.get("timestamp"))]
    night_count = len(night_events)
    if night_count >= 10:
        score += _add_rule_finding(
            findings,
            "night_activity",
            f"{night_count} events occurred between 22:00 and 06:00.",
            [_format_event_brief(event) for event in night_events[:5]],
        )

    # 4. Cloud service access
    cloud_domains = ("dropbox", "drive.google", "google drive", "onedrive", "mega.nz", "box.com")
    cloud_hits = []
    for event in web_events:
        target = f"{event.get('target', '')} {event.get('summary', '')}".lower()
        if any(domain in target for domain in cloud_domains):
            cloud_hits.append(event)
    if cloud_hits:
        score += _add_rule_finding(
            findings,
            "cloud_access",
            f"{len(cloud_hits)} browser events matched common cloud storage domains.",
            [_format_event_brief(event) for event in cloud_hits[:5]],
        )

    # 5. Archive file creation
    archive_exts = (".zip", ".rar", ".7z")
    archive_hits = []
    for entry in filesystem_entries:
        target = str(entry.get("source_path") or entry.get("entry_name") or "").lower()
        if target.endswith(archive_exts):
            archive_hits.append(entry)
    if archive_hits:
        score += _add_rule_finding(
            findings,
            "archive_created",
            f"{len(archive_hits)} archive-related filesystem records were identified.",
            [_format_entry_brief(entry) for entry in archive_hits[:5]],
        )

    # 6. Large mail attachments
    large_mail = []
    for event in mail_events:
        detail = event.get("detail", {}) or {}
        attachment_count = detail.get("attachment_count") or 0
        attachments = detail.get("attachments", []) or []
        max_size = max((_bytes_to_mb(item.get("size")) for item in attachments if isinstance(item, dict)), default=0.0)
        if attachment_count and max_size >= 5:
            large_mail.append((attachment_count, max_size, event))
    if large_mail:
        largest = max(large_mail, key=lambda item: item[1])
        score += _add_rule_finding(
            findings,
            "large_mail_attachment",
            f"Mail artifacts included attachments up to {largest[1]:.1f} MB.",
            [_format_event_brief(item[2]) for item in large_mail[:3]],
        )

    # 7. Suspicious transfer tools
    suspicious_tools = ("filezilla", "rclone")
    tool_hits = []
    for event in exec_events:
        text = f"{event.get('target', '')} {event.get('summary', '')}".lower()
        if any(tool in text for tool in suspicious_tools):
            tool_hits.append(event)
    if tool_hits:
        score += _add_rule_finding(
            findings,
            "suspicious_tool",
            f"{len(tool_hits)} execution events matched FileZilla or rclone.",
            [_format_event_brief(event) for event in tool_hits[:5]],
        )

    # 8. Print then USB
    print_events = [e for e in timeline if e.get("artifact_type") == "spool"]
    for print_event in print_events:
        ts = print_event.get("timestamp")
        if not ts:
            continue
        window_end = ts + timedelta(minutes=30)
        matched_usb = [u for u in usb_events if u.get("timestamp") and ts <= u["timestamp"] <= window_end]
        if matched_usb:
            score += _add_rule_finding(
                findings,
                "print_then_usb",
                "A USB event occurred within 30 minutes of a print event.",
                [_format_event_brief(print_event)] + [_format_event_brief(event) for event in matched_usb[:3]],
            )
            break

    # 9. Delete activity before USB
    for usb in usb_events:
        ts = usb.get("timestamp")
        if not ts:
            continue
        window_start = ts - timedelta(hours=1)
        delete_hits = []
        for event in filesystem_events:
            if not event.get("timestamp"):
                continue
            action = str(event.get("action", "")).lower()
            target = str(event.get("target", "")).lower()
            if window_start <= event["timestamp"] <= ts and ("delete" in action or "$recycle.bin" in target):
                delete_hits.append(event)
        if len(delete_hits) >= 3:
            score += _add_rule_finding(
                findings,
                "delete_before_usb",
                f"{len(delete_hits)} delete-like events occurred within 1 hour before USB activity.",
                [_format_event_brief(event) for event in delete_hits[:5]] + [_format_event_brief(usb)],
            )
            break

    # 10. Repeated logon failures
    fail_times = []
    fail_entries = []
    for entry in eventlog_entries:
        if entry.get("event_id") == 4625 and entry.get("timestamp"):
            fail_times.append(entry["timestamp"])
            fail_entries.append(entry)
    fail_times.sort()
    for idx, ts in enumerate(fail_times):
        window_end = ts + timedelta(minutes=10)
        count = sum(1 for item in fail_times[idx:] if item <= window_end)
        if count >= 5:
            evidence = []
            for entry in fail_entries:
                ets = entry.get("timestamp")
                if ets and ts <= ets <= window_end:
                    evidence.append(_format_event_brief({
                        "timestamp": ets,
                        "target": f"Event 4625 | {entry.get('subject_user_name') or 'Unknown user'}",
                    }))
            score += _add_rule_finding(
                findings,
                "repeated_logon_failure",
                f"{count} failed logon events were recorded within 10 minutes.",
                evidence[:5],
            )
            break

    # 11. New storage device first use
    usb_entries = artifact_cache.get("usb", [])
    first_use_hits = [
        entry for entry in usb_entries
        if entry.get("first_install_time")
    ]
    if first_use_hits:
        score += _add_rule_finding(
            findings,
            "new_storage_device",
            f"{len(first_use_hits)} USB artifacts included a first-install timestamp, indicating first-seen device usage.",
            [
                f"{entry.get('friendly_name') or entry.get('product') or entry.get('serial_number')} | "
                f"first_install={entry.get('first_install_time')}"
                for entry in first_use_hits[:5]
            ],
        )

    risk_level = "낮음"
    if score >= 60:
        risk_level = "심각"
    elif score >= 40:
        risk_level = "높음"
    elif score >= 20:
        risk_level = "보통"

    category_counts = Counter(event.get("artifact_type") for event in timeline)
    return {
        "score": score,
        "level": risk_level,
        "findings": findings,
        "timeline_event_count": len(timeline),
        "artifact_event_counts": dict(category_counts),
    }


class RiskDashboardWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._findings = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        cards = QHBoxLayout()
        self.score_card = self._make_stat_card("위험 점수", "0")
        self.level_card = self._make_stat_card("위험도", "낮음")
        self.findings_card = self._make_stat_card("탐지 규칙", "0")
        self.events_card = self._make_stat_card("타임라인 이벤트", "0")
        cards.addWidget(self.score_card["box"])
        cards.addWidget(self.level_card["box"])
        cards.addWidget(self.findings_card["box"])
        cards.addWidget(self.events_card["box"])
        layout.addLayout(cards)

        body_split = QSplitter(Qt.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)
        left_label = QLabel("탐지된 규칙")
        left_label.setObjectName("risk_section")
        self.finding_list = QListWidget()
        self.finding_list.currentRowChanged.connect(self._show_finding_detail)
        left_layout.addWidget(left_label)
        left_layout.addWidget(self.finding_list)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)
        right_label = QLabel("규칙 상세")
        right_label.setObjectName("risk_section")
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFont(QFont(UI_FONT_FAMILY, 10))
        right_layout.addWidget(right_label)
        right_layout.addWidget(self.detail_text)

        body_split.addWidget(left_panel)
        body_split.addWidget(right_panel)
        body_split.setSizes([420, 760])
        layout.addWidget(body_split, stretch=1)

    def _make_stat_card(self, title: str, value: str) -> dict:
        box = QGroupBox()
        box.setObjectName("risk_card")
        card_layout = QVBoxLayout(box)
        card_layout.setContentsMargins(12, 10, 12, 10)
        title_label = QLabel(title)
        title_label.setObjectName("risk_card_title")
        value_label = QLabel(value)
        value_label.setObjectName("risk_card_value")
        card_layout.addWidget(title_label)
        card_layout.addWidget(value_label)
        return {"box": box, "title": title_label, "value": value_label}

    def set_result(self, result: dict) -> None:
        self._findings = result.get("findings", [])
        self.score_card["value"].setText(str(result.get("score", 0)))
        level = result.get("level", "낮음")
        self.level_card["value"].setText(level)
        self.findings_card["value"].setText(str(len(self._findings)))
        self.events_card["value"].setText(str(result.get("timeline_event_count", 0)))
        self._set_level_color(level)
        self.finding_list.clear()
        for finding in self._findings:
            item = QListWidgetItem(
                f"[{finding.get('severity')}] +{finding.get('score')}  {finding.get('name')}"
            )
            item.setData(Qt.UserRole, finding)
            severity = finding.get("severity")
            if severity == "심각":
                item.setForeground(QColor(C_RED))
            elif severity == "높음":
                item.setForeground(QColor(C_AMBER))
            elif severity == "보통":
                item.setForeground(QColor(C_GREEN))
            self.finding_list.addItem(item)
        if self.finding_list.count():
            self.finding_list.setCurrentRow(0)
        else:
            self.detail_text.setPlainText("탐지된 위험 규칙이 없습니다.")

    def _set_level_color(self, level: str) -> None:
        color = C_GREEN
        if level == "심각":
            color = C_RED
        elif level == "높음":
            color = C_AMBER
        elif level == "보통":
            color = C_BLUE
        self.level_card["value"].setStyleSheet(f"color: {color}; font-weight: 700;")

    def _show_finding_detail(self, row: int) -> None:
        if row < 0 or row >= self.finding_list.count():
            self.detail_text.clear()
            return
        finding = self.finding_list.item(row).data(Qt.UserRole)
        lines = [
            f"규칙: {finding.get('name')}",
            f"심각도: {finding.get('severity')}",
            f"점수: {finding.get('score')}",
            f"임계값: {finding.get('threshold')}",
            "",
            f"요약: {finding.get('detail')}",
            "",
            "증거:",
        ]
        evidence_lines = finding.get("evidence_lines") or []
        if evidence_lines:
            lines.extend(f"- {line}" for line in evidence_lines)
        else:
            lines.append("- 기록된 증거가 없습니다.")
        self.detail_text.setPlainText("\n".join(lines))


class CaseFileSystemTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.handler = None
        self._item_meta = {}
        self._table_entries = []
        self._table_fs = None
        self._dir_history: list[tuple[object, object, str]] = []
        self._forward_history: list[tuple[object, object, str]] = []
        self._history_guard = False
        self._current_dir: tuple[object, object, str] | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        splitter = QSplitter(Qt.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        header = QLabel("  Directory Tree")
        header.setObjectName("panel_header")
        header.setFixedHeight(28)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemExpanded.connect(self._on_tree_expanded)
        self.tree.itemClicked.connect(self._on_tree_clicked)
        left_layout.addWidget(header)
        left_layout.addWidget(self.tree)

        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(0, 0, 0, 0)
        path_bar = QWidget()
        path_bar_layout = QHBoxLayout(path_bar)
        path_bar_layout.setContentsMargins(0, 0, 0, 0)
        path_bar_layout.setSpacing(0)
        self.back_btn = QPushButton("◀")
        self.back_btn.setFixedHeight(28)
        self.back_btn.setFixedWidth(34)
        self.back_btn.setEnabled(False)
        self.back_btn.clicked.connect(self._go_back)
        self.forward_btn = QPushButton("▶")
        self.forward_btn.setFixedHeight(28)
        self.forward_btn.setFixedWidth(34)
        self.forward_btn.setEnabled(False)
        self.forward_btn.clicked.connect(self._go_forward)
        path_label = QLabel("  Path: /")
        path_label.setObjectName("path_bar")
        path_label.setFixedHeight(28)
        self.path_label = path_label
        path_bar_layout.addWidget(self.back_btn)
        path_bar_layout.addWidget(self.forward_btn)
        path_bar_layout.addWidget(path_label, stretch=1)
        self.table = CopyableTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Name", "Size", "Type", "Inode"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(False)
        table_header = self.table.horizontalHeader()
        table_header.setSectionResizeMode(0, QHeaderView.Stretch)
        table_header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        table_header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        table_header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.itemClicked.connect(self._on_file_clicked)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._open_file_context_menu)
        center_layout.addWidget(path_bar)
        center_layout.addWidget(self.table)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        preview_header = QLabel("  File Preview")
        preview_header.setObjectName("panel_header")
        preview_header.setFixedHeight(28)
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setFont(QFont(UI_FONT_FAMILY, 10))
        right_layout.addWidget(preview_header)
        right_layout.addWidget(self.preview)

        splitter.addWidget(left_panel)
        splitter.addWidget(center_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([280, 640, 420])
        layout.addWidget(splitter)

    def set_handler(self, handler: ImageHandler) -> None:
        self.handler = handler
        self._item_meta.clear()
        self._dir_history.clear()
        self._forward_history.clear()
        self._current_dir = None
        self.back_btn.setEnabled(False)
        self.forward_btn.setEnabled(False)
        self.tree.clear()
        self.table.setRowCount(0)
        self.preview.clear()
        if handler is None:
            return
        root_item = QTreeWidgetItem([f"[IMG] {os.path.basename(handler.image_path)}"])
        root_item.setForeground(0, QColor(C_AMBER))
        self.tree.addTopLevelItem(root_item)
        for volume in handler.volumes:
            vol_item = QTreeWidgetItem([f"[VOL] {volume['desc']}"])
            vol_item.setForeground(0, QColor(C_BLUE))
            vol_item.addChild(QTreeWidgetItem(["Loading..."]))
            self._item_meta[id(vol_item)] = {
                "fs": volume["fs"],
                "inode": None,
                "path": "/",
                "is_dir": True,
            }
            root_item.addChild(vol_item)
        root_item.setExpanded(True)

    def _on_tree_expanded(self, item) -> None:
        meta = self._item_meta.get(id(item))
        if not meta or item.childCount() != 1 or item.child(0).text(0) != "Loading...":
            return
        entries = self.handler.list_directory(meta["fs"], meta["inode"], meta["path"])
        item.takeChildren()
        for entry in entries:
            label = f"[DIR] {entry.name}" if entry.is_dir else entry.name
            child = QTreeWidgetItem([label])
            if entry.is_dir:
                child.addChild(QTreeWidgetItem(["Loading..."]))
            self._item_meta[id(child)] = {
                "fs": entry._fs,
                "inode": entry.inode,
                "path": entry.path,
                "is_dir": entry.is_dir,
            }
            item.addChild(child)

    def _on_tree_clicked(self, item) -> None:
        meta = self._item_meta.get(id(item))
        if not meta:
            return
        self._push_history(meta["fs"], meta["inode"], meta["path"])
        entries = self.handler.list_directory(meta["fs"], meta["inode"], meta["path"])
        self._table_entries = entries
        self._table_fs = meta["fs"]
        self._current_dir = (meta["fs"], meta["inode"], meta["path"])
        self.path_label.setText(f"  Path: {meta['path']}")
        self.table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            values = [
                entry.name,
                self._fmt_size(entry.size) if not entry.is_dir else "",
                "DIR" if entry.is_dir else self._ext(entry.name),
                str(entry.inode),
            ]
            for col, value in enumerate(values):
                item_widget = QListWidgetItem(value)
            for col, value in enumerate(values):
                from PyQt5.QtWidgets import QStyle, QTableWidgetItem
                cell = QTableWidgetItem(value)
                if col == 0:
                    cell.setIcon(self.style().standardIcon(QStyle.SP_DirIcon if entry.is_dir else QStyle.SP_FileIcon))
                cell.setData(Qt.UserRole, entry)
                self.table.setItem(row, col, cell)

    def _on_file_clicked(self, item) -> None:
        entry = item.data(Qt.UserRole)
        if entry is None:
            return
        if entry.is_dir:
            self._push_history(entry._fs, entry.inode, entry.path)
            entries = self.handler.list_directory(entry._fs, entry.inode, entry.path)
            self._table_entries = entries
            self._table_fs = entry._fs
            self._current_dir = (entry._fs, entry.inode, entry.path)
            self.path_label.setText(f"  Path: {entry.path}")
            self.table.setRowCount(len(entries))
            for row, child in enumerate(entries):
                values = [
                    child.name,
                    self._fmt_size(child.size) if not child.is_dir else "",
                    "DIR" if child.is_dir else self._ext(child.name),
                    str(child.inode),
                ]
                for col, value in enumerate(values):
                    from PyQt5.QtWidgets import QStyle, QTableWidgetItem
                    cell = QTableWidgetItem(value)
                    if col == 0:
                        cell.setIcon(self.style().standardIcon(QStyle.SP_DirIcon if child.is_dir else QStyle.SP_FileIcon))
                    cell.setData(Qt.UserRole, child)
                    self.table.setItem(row, col, cell)
            self.preview.setPlainText("Directory selected.")
            return
        data = self.handler.read_file(entry._fs, entry.inode, max_bytes=8192)
        if b"\x00" in data[:1024]:
            hex_lines = []
            for idx in range(0, min(len(data), 1024), 16):
                chunk = data[idx:idx + 16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                hex_lines.append(f"{idx:08X}  {hex_part:<47}  {ascii_part}")
            self.preview.setPlainText("\n".join(hex_lines))
        else:
            self.preview.setPlainText(data.decode("utf-8", errors="replace"))

    def _push_history(self, fs, inode, path: str) -> None:
        if self._history_guard:
            return
        if self._current_dir is not None:
            cur_fs, cur_inode, cur_path = self._current_dir
            if cur_fs is fs and cur_inode == inode and cur_path == path:
                return
            self._dir_history.append(self._current_dir)
            self._forward_history.clear()
        self.back_btn.setEnabled(bool(self._dir_history))
        self.forward_btn.setEnabled(bool(self._forward_history))

    def _go_back(self) -> None:
        if not self.handler or not self._dir_history:
            return
        fs, inode, path = self._dir_history.pop()
        if self._current_dir is not None:
            self._forward_history.append(self._current_dir)
        self.back_btn.setEnabled(bool(self._dir_history))
        self.forward_btn.setEnabled(bool(self._forward_history))
        self._history_guard = True
        try:
            entries = self.handler.list_directory(fs, inode, path)
            self._table_entries = entries
            self._table_fs = fs
            self._current_dir = (fs, inode, path)
            self.path_label.setText(f"  Path: {path}")
            self.table.setRowCount(len(entries))
            for row, entry in enumerate(entries):
                values = [
                    entry.name,
                    self._fmt_size(entry.size) if not entry.is_dir else "",
                    "DIR" if entry.is_dir else self._ext(entry.name),
                    str(entry.inode),
                ]
                for col, value in enumerate(values):
                    from PyQt5.QtWidgets import QStyle, QTableWidgetItem
                    cell = QTableWidgetItem(value)
                    if col == 0:
                        cell.setIcon(self.style().standardIcon(QStyle.SP_DirIcon if entry.is_dir else QStyle.SP_FileIcon))
                    cell.setData(Qt.UserRole, entry)
                    self.table.setItem(row, col, cell)
            self.preview.setPlainText("Directory selected.")
        finally:
            self._history_guard = False

    def _go_forward(self) -> None:
        if not self.handler or not self._forward_history:
            return
        fs, inode, path = self._forward_history.pop()
        if self._current_dir is not None:
            self._dir_history.append(self._current_dir)
        self.back_btn.setEnabled(bool(self._dir_history))
        self.forward_btn.setEnabled(bool(self._forward_history))
        self._history_guard = True
        try:
            entries = self.handler.list_directory(fs, inode, path)
            self._table_entries = entries
            self._table_fs = fs
            self._current_dir = (fs, inode, path)
            self.path_label.setText(f"  Path: {path}")
            self.table.setRowCount(len(entries))
            for row, entry in enumerate(entries):
                values = [
                    entry.name,
                    self._fmt_size(entry.size) if not entry.is_dir else "",
                    "DIR" if entry.is_dir else self._ext(entry.name),
                    str(entry.inode),
                ]
                for col, value in enumerate(values):
                    from PyQt5.QtWidgets import QStyle, QTableWidgetItem
                    cell = QTableWidgetItem(value)
                    if col == 0:
                        cell.setIcon(self.style().standardIcon(QStyle.SP_DirIcon if entry.is_dir else QStyle.SP_FileIcon))
                    cell.setData(Qt.UserRole, entry)
                    self.table.setItem(row, col, cell)
            self.preview.setPlainText("Directory selected.")
        finally:
            self._history_guard = False

    def _open_file_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if item is not None:
            self.table.selectRow(item.row())
        selected = self.table.currentItem()
        if selected is None:
            return
        entry = selected.data(Qt.UserRole)
        if entry is None:
            return

        menu = QMenu(self)
        copy_link_action = menu.addAction("Copy Link")
        export_action = menu.addAction("Export")
        chosen = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if chosen == copy_link_action:
            QApplication.clipboard().setText(str(getattr(entry, "path", "") or ""))
        elif chosen == export_action:
            self._export_selected_entry(entry)

    def _export_selected_entry(self, entry) -> None:
        if self.handler is None or entry is None:
            return
        destination_dir = QFileDialog.getExistingDirectory(
            self,
            "Export Destination Folder",
            os.path.expanduser("~"),
        )
        if not destination_dir:
            return
        try:
            extracted = self.handler.extract_entry(entry, destination_dir)
            self.preview.append(f"\n[INFO] Exported: {extracted} item(s) -> {destination_dir}")
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", f"파일 추출 중 오류가 발생했습니다.\n{exc}")

    @staticmethod
    def _fmt_size(size) -> str:
        value = float(size or 0)
        for unit in ("B", "KB", "MB", "GB"):
            if value < 1024:
                return f"{value:.1f} {unit}"
            value /= 1024
        return f"{value:.1f} TB"

    @staticmethod
    def _ext(name: str) -> str:
        ext = os.path.splitext(name)[1].lower()
        return ext.lstrip(".").upper() if ext else "FILE"

    @staticmethod
    def _normalize_fs_path(path: str) -> str:
        normalized = (path or "/").replace("\\", "/")
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        while "//" in normalized:
            normalized = normalized.replace("//", "/")
        if len(normalized) > 1:
            normalized = normalized.rstrip("/")
        return normalized or "/"

    @staticmethod
    def _split_fs_path(path: str) -> tuple[str, str]:
        normalized = CaseFileSystemTab._normalize_fs_path(path)
        if normalized == "/":
            return "/", ""
        parent, _, name = normalized.rpartition("/")
        return (parent or "/"), name

    def open_path(self, path: str) -> bool:
        if self.handler is None:
            return False
        target_path = self._normalize_fs_path(path)
        parent_path, name = self._split_fs_path(target_path)
        lower_name = name.lower()
        for volume in getattr(self.handler, "volumes", []):
            fs = volume.get("fs")
            if fs is None:
                continue
            try:
                entries = self.handler.list_directory(fs, path=parent_path)
            except Exception:
                continue
            if not entries:
                continue
            self._table_entries = entries
            self._table_fs = fs
            self.path_label.setText(f"  Path: {parent_path}")
            self.table.setRowCount(len(entries))
            selected_row = -1
            from PyQt5.QtWidgets import QStyle, QTableWidgetItem
            for row, entry in enumerate(entries):
                values = [
                    entry.name,
                    self._fmt_size(entry.size) if not entry.is_dir else "",
                    "DIR" if entry.is_dir else self._ext(entry.name),
                    str(entry.inode),
                ]
                for col, value in enumerate(values):
                    cell = QTableWidgetItem(value)
                    if col == 0:
                        cell.setIcon(self.style().standardIcon(QStyle.SP_DirIcon if entry.is_dir else QStyle.SP_FileIcon))
                    cell.setData(Qt.UserRole, entry)
                    self.table.setItem(row, col, cell)
                if self._normalize_fs_path(entry.path) == target_path or entry.name.lower() == lower_name:
                    selected_row = row
            if selected_row >= 0:
                self.table.selectRow(selected_row)
                item = self.table.item(selected_row, 0)
                if item is not None:
                    self.table.scrollToItem(item)
                    self._on_file_clicked(item)
                return True
        return False


class CaseWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.case_config: Optional[CaseConfig] = None
        self.handler = None
        self.artifact_cache = {}
        self._artifact_file_map: dict[str, str] = {}
        self._timeline_file_path: str = ""
        self.timeline_entries = []
        self.risk_result = {}
        self._timeline_loaded = False
        self._workers = []
        self._progress_dialog = None
        self._build_ui()
        self._apply_style()

    def _build_ui(self) -> None:
        self.setWindowTitle("insider_exfil_tool")
        icon_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "Icon.png"))
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.setGeometry(100, 100, 1560, 940)
        self.setMinimumSize(1180, 760)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        self.toolbar = toolbar
        self.new_case_action = QAction("새 사건", self)
        self.new_case_action.triggered.connect(self.show_case_intake)
        self.open_case_action = QAction("사건 열기", self)
        self.open_case_action.triggered.connect(self._open_saved_case)
        self.rebuild_action = QAction("사건 재분석", self)
        self.rebuild_action.triggered.connect(self._rebuild_current_case)
        self.rebuild_action.setVisible(False)
        toolbar.addAction(self.new_case_action)
        toolbar.addAction(self.open_case_action)
        toolbar.addAction(self.rebuild_action)

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)

        self.stack = QStackedWidget()
        root.addWidget(self.stack, stretch=1)

        self.start_page = StartPageWidget()
        self.start_page.new_case_requested.connect(self.show_case_intake)
        self.start_page.open_case_requested.connect(self._open_saved_case)
        self.start_page.open_recent_requested.connect(self._open_recent_case_path)
        self.stack.addWidget(self.start_page)

        self.intake_page = CaseIntakeWidget()
        self.intake_page.start_requested.connect(self._start_case_build)
        self.intake_page.image_preview_requested.connect(self._load_image_preview)
        self.stack.addWidget(self.intake_page)

        self.analysis_page = QWidget()
        analysis_layout = QVBoxLayout(self.analysis_page)
        analysis_layout.setContentsMargins(0, 0, 0, 0)
        analysis_layout.setSpacing(10)

        self.case_header = QLabel("사건이 로드되지 않았습니다.")
        self.case_header.setObjectName("case_header")
        self.case_summary = QLabel("사건을 생성하면 아티팩트 파싱, 타임라인 생성, 위험도 분석이 시작됩니다.")
        self.case_summary.setObjectName("case_summary")
        self.case_summary.setWordWrap(True)
        analysis_layout.addWidget(self.case_header)
        analysis_layout.addWidget(self.case_summary)

        self.result_tabs = QTabWidget()
        self.result_tabs.setObjectName("main_tabs")

        self.overview_text = QTextEdit()
        self.overview_text.setReadOnly(True)
        self.overview_text.setFont(QFont(UI_FONT_FAMILY, 10))
        self.result_tabs.addTab(self.overview_text, "Overview")

        self.file_system_tab = CaseFileSystemTab()
        self.result_tabs.addTab(self.file_system_tab, "File System")

        self.timeline_widget = TimelineExplorerWidget([], self)
        self.timeline_widget.detail_navigation_requested.connect(self._open_timeline_detail_target)
        self.timeline_tab_index = self.result_tabs.addTab(self.timeline_widget, "Timeline")

        risk_panel = QWidget()
        risk_layout = QVBoxLayout(risk_panel)
        risk_layout.setContentsMargins(0, 0, 0, 0)
        self.risk_dashboard = RiskDashboardWidget()
        risk_layout.addWidget(self.risk_dashboard)
        self.result_tabs.addTab(risk_panel, "Risk Analysis")

        self.artifact_list = QListWidget()
        self.artifact_event_table = CopyableTableWidget()
        self.artifact_event_table.setColumnCount(4)
        self.artifact_event_table.setHorizontalHeaderLabels(["시간", "행위", "대상", "요약"])
        self.artifact_event_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.artifact_event_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.artifact_event_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.artifact_event_table.verticalHeader().setVisible(False)
        self.artifact_event_table.setAlternatingRowColors(True)
        self.artifact_event_table.setWordWrap(False)
        header = self.artifact_event_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        self.artifact_detail = QTextEdit()
        self.artifact_detail.setReadOnly(True)
        self.artifact_detail.setFont(QFont(UI_FONT_FAMILY, 10))
        artifact_panel = QSplitter(Qt.Horizontal)
        artifact_panel.addWidget(self.artifact_list)
        artifact_panel.addWidget(self.artifact_event_table)
        artifact_panel.addWidget(self.artifact_detail)
        artifact_panel.setSizes([260, 620, 420])
        self.artifact_list.currentItemChanged.connect(self._on_artifact_result_changed)
        self.artifact_event_table.itemSelectionChanged.connect(self._on_artifact_event_selected)
        self.result_tabs.addTab(artifact_panel, "Artifact Results")
        self.result_tabs.currentChanged.connect(self._on_result_tab_changed)

        analysis_layout.addWidget(self.result_tabs, stretch=1)

        self.stack.addWidget(self.analysis_page)
        self.stack.setCurrentWidget(self.start_page)

        self.setCentralWidget(central)
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self._refresh_recent_cases()
        self._set_start_mode()
        self.status.showMessage("새 사건 또는 사건 열기를 선택하세요.")

    def _apply_style(self) -> None:
        self.setFont(QFont(UI_FONT_FAMILY, 10))
        self.setStyleSheet(
            f"""
            QMainWindow, QWidget {{
                background: {C_BG};
                color: {C_TEXT};
                font-family: 'Malgun Gothic', sans-serif;
                font-size: 10pt;
            }}
            QToolBar {{
                background: {C_HEADER};
                border-bottom: 1px solid {C_BORDER};
                spacing: 6px;
                padding: 6px 10px;
            }}
            QToolBar QToolButton {{
                background: transparent;
                color: {C_TEXT};
                border-radius: 6px;
                padding: 6px 14px;
                font-weight: 600;
            }}
            QToolBar QToolButton:hover {{
                background: {C_SELECT};
                color: {C_BLUE};
            }}
            QLabel#case_header {{
                font-size: 18pt;
                font-weight: 700;
                color: {C_TEXT};
            }}
            QLabel#case_summary {{
                color: {C_SUBTEXT};
            }}
            QLabel#risk_section {{
                color: {C_BLUE};
                font-weight: 700;
            }}
            QLabel#risk_card_title {{
                color: {C_SUBTEXT};
                font-size: 9pt;
            }}
            QLabel#risk_card_value {{
                color: {C_TEXT};
                font-size: 18pt;
                font-weight: 700;
            }}
            QGroupBox#risk_card {{
                background: {C_PANEL};
                border: 1px solid {C_BORDER};
                border-radius: 10px;
            }}
            QLabel#panel_header {{
                background: {C_HEADER};
                color: {C_BLUE};
                font-weight: 700;
                border-bottom: 1px solid {C_BORDER};
            }}
            QLabel#path_bar {{
                background: {C_PANEL};
                color: {C_SUBTEXT};
                border-bottom: 1px solid {C_BORDER};
            }}
            QTabWidget#main_tabs::pane {{
                border: 1px solid {C_BORDER};
                background: {C_PANEL};
            }}
            QTabBar::tab {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                padding: 8px 18px;
                margin-right: 2px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }}
            QTabBar::tab:selected {{
                background: {C_PANEL};
                color: {C_BLUE};
                border-bottom: 2px solid {C_BLUE};
            }}
            QTextEdit, QTreeWidget, QTableWidget, QListWidget {{
                background: {C_PANEL};
                border: 1px solid {C_BORDER};
            }}
            QHeaderView::section {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                border: none;
                border-right: 1px solid {C_BORDER};
                border-bottom: 1px solid {C_BORDER};
                padding: 6px 8px;
            }}
            QTreeWidget::item:selected,
            QTableWidget::item:selected,
            QListWidget::item:selected {{
                background: {C_SELECT};
                color: {C_BLUE};
            }}
            QGroupBox {{
                background: {C_PANEL};
                border: 1px solid {C_BORDER};
                border-radius: 8px;
                margin-top: 10px;
                font-weight: 700;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
                color: {C_BLUE};
            }}
            """
        )

    def _recent_cases_file(self) -> str:
        base_dir = os.path.join(os.path.expanduser("~"), ".insider_exfil_tool")
        os.makedirs(base_dir, exist_ok=True)
        return os.path.join(base_dir, "recent_cases.json")

    def _load_recent_cases(self) -> list[dict]:
        path = self._recent_cases_file()
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as stream:
                data = json.load(stream)
            if not isinstance(data, list):
                return []
            normalized = []
            for row in data:
                if not isinstance(row, dict):
                    continue
                case_dir = str(row.get("case_dir") or "").strip()
                display_name = str(row.get("display_name") or "").strip()
                if case_dir and os.path.isdir(case_dir):
                    normalized.append({"case_dir": case_dir, "display_name": display_name})
            return normalized[:20]
        except Exception:
            return []

    def _write_recent_cases(self, cases: list[dict]) -> None:
        path = self._recent_cases_file()
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(cases[:20], stream, ensure_ascii=False, indent=2)

    def _save_recent_case(self, case_dir: str, display_name: str) -> None:
        if not case_dir or not os.path.isdir(case_dir):
            return
        name = (display_name or "").strip() or os.path.basename(case_dir)
        cases = self._load_recent_cases()
        cases = [row for row in cases if row.get("case_dir") != case_dir]
        cases.insert(0, {"case_dir": case_dir, "display_name": name})
        self._write_recent_cases(cases)
        self._refresh_recent_cases()

    def _refresh_recent_cases(self) -> None:
        self.start_page.set_recent_cases(self._load_recent_cases())

    def _set_start_mode(self) -> None:
        if hasattr(self, "toolbar"):
            self.toolbar.setVisible(False)
        self.rebuild_action.setVisible(False)
        self.stack.setCurrentWidget(self.start_page)

    def _set_work_mode(self) -> None:
        if hasattr(self, "toolbar"):
            self.toolbar.setVisible(True)

    def _open_recent_case_path(self, case_dir: str) -> None:
        self._show_progress_dialog("사건 불러오는 중", 100)
        if not case_dir:
            self._finish_progress_dialog("사건 경로 없음")
            QMessageBox.information(self, "사건 열기", "열 수 있는 사건 경로가 없습니다.")
            return
        case_json_path = os.path.join(case_dir, "case.json")
        risk_json_path = os.path.join(case_dir, "risk_result.json")
        timeline_json_path = os.path.join(case_dir, "timeline.json")
        artifacts_dir = os.path.join(case_dir, "artifacts")
        if self._progress_dialog is not None:
            self._progress_dialog.set_progress(10)
            self._progress_dialog.set_message("사건 파일 확인 중...")
            QApplication.processEvents()
        if not os.path.exists(case_json_path):
            self._finish_progress_dialog("case.json 없음")
            QMessageBox.warning(self, "사건 열기 실패", "선택한 경로에 case.json 파일이 없습니다.")
            return
        try:
            with open(case_json_path, "r", encoding="utf-8") as stream:
                case_data = json.load(stream)
            with open(risk_json_path, "r", encoding="utf-8") as stream:
                risk_data = json.load(stream)
            if self._progress_dialog is not None:
                self._progress_dialog.set_progress(35)
                self._progress_dialog.set_message("기본 사건 데이터 로드 중...")
                QApplication.processEvents()
        except Exception as exc:
            self._finish_progress_dialog("사건 파일 읽기 실패")
            QMessageBox.critical(self, "사건 열기 실패", f"사건 파일을 읽는 중 오류가 발생했습니다.\n{exc}")
            return

        self.case_config = CaseConfig(
            case_number=str(case_data.get("case_number") or ""),
            case_name=str(case_data.get("case_name") or ""),
            investigator=str(case_data.get("investigator") or ""),
            image_path=str(case_data.get("image_path") or ""),
            partition_offsets=[int(v) for v in (case_data.get("selected_partitions") or [])],
            artifact_ids=[str(v) for v in (case_data.get("selected_artifacts") or [])],
            case_storage_dir=os.path.dirname(case_dir),
            case_output_name=str(case_data.get("case_output_name") or case_data.get("case_name") or ""),
            case_output_dir=case_dir,
        )

        self.artifact_cache = {}
        self._artifact_file_map = {}
        if os.path.isdir(artifacts_dir):
            for artifact_id in self.case_config.artifact_ids:
                artifact_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
                if os.path.exists(artifact_path):
                    self._artifact_file_map[artifact_id] = artifact_path
        if self._progress_dialog is not None:
            self._progress_dialog.set_progress(70)
            self._progress_dialog.set_message("아티팩트 인덱스 구성 중...")
            QApplication.processEvents()

        self._timeline_file_path = timeline_json_path if os.path.exists(timeline_json_path) else ""
        self.timeline_entries = []
        self.risk_result = risk_data if isinstance(risk_data, dict) else {}
        self.handler = None
        self.file_system_tab.set_handler(None)
        if self._progress_dialog is not None:
            self._progress_dialog.set_progress(82)
            self._progress_dialog.set_message("증거 이미지 연결 중...")
            QApplication.processEvents()
        image_path = self.case_config.image_path
        if image_path and os.path.exists(image_path):
            try:
                reopened = ImageHandler()
                reopened.open(image_path)
                selected_offsets = set(self.case_config.partition_offsets or [])
                if selected_offsets:
                    reopened.volumes = [
                        vol for vol in reopened.volumes
                        if int(vol.get("offset", 0)) in selected_offsets
                    ]
                self.handler = reopened
                self.file_system_tab.set_handler(self.handler)
            except Exception as exc:
                self._log(f"[WARN] 저장 사건 이미지 재연결 실패: {exc}")

        self._populate_case_views()
        self._set_work_mode()
        self.rebuild_action.setVisible(False)
        self.stack.setCurrentWidget(self.analysis_page)
        self._save_recent_case(case_dir, self.case_config.case_output_name or self.case_config.case_name)
        if self._progress_dialog is not None:
            self._progress_dialog.set_progress(95)
            self._progress_dialog.set_message("사건 화면 준비 중...")
            QApplication.processEvents()
        self._finish_progress_dialog("사건 불러오기 완료")
        self.status.showMessage("저장된 사건을 불러왔습니다.")

    @staticmethod
    def _parse_iso_datetime(value):
        if isinstance(value, datetime):
            return value
        if not isinstance(value, str):
            return value
        text = value.strip()
        if not text:
            return value
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return datetime.fromisoformat(text)
        except Exception:
            return value

    def _restore_timeline_datetimes(self, events: list[dict]) -> list[dict]:
        restored = []
        for event in events:
            if not isinstance(event, dict):
                continue
            row = dict(event)
            if "timestamp" in row:
                row["timestamp"] = self._parse_iso_datetime(row.get("timestamp"))
            for key in ("created_time", "modified_time", "accessed_time", "changed_time"):
                if key in row:
                    row[key] = self._parse_iso_datetime(row.get(key))
            restored.append(row)
        return restored

    def show_case_intake(self) -> None:
        self.intake_page.reset()
        self._set_work_mode()
        self.rebuild_action.setVisible(False)
        self.stack.setCurrentWidget(self.intake_page)
        self.status.showMessage("사건 정보를 입력하고 증거 이미지를 불러오세요.")

    def _open_saved_case(self) -> None:
        default_dir = _default_case_storage_dir()
        case_dir = QFileDialog.getExistingDirectory(
            self,
            "사건 폴더 선택",
            default_dir if os.path.isdir(default_dir) else os.path.expanduser("~"),
        )
        if not case_dir:
            self.status.showMessage("사건 열기가 취소되었습니다.")
            return
        self._open_recent_case_path(case_dir)

    def _load_image_preview(self, image_path: str) -> None:
        worker = ImagePreviewWorker(image_path)
        worker.done.connect(self._on_image_preview_ready)
        worker.error.connect(self._on_image_preview_error)
        worker.finished.connect(self._cleanup_finished_worker)
        self._workers.append(worker)
        self.status.showMessage("읽을 수 있는 파티션을 스캔하는 중입니다...")
        worker.start()

    def _on_image_preview_ready(self, preview_data: dict) -> None:
        self.intake_page.set_preview_result(preview_data)
        self.status.showMessage("파티션 스캔이 완료되었습니다. 분석할 파티션과 아티팩트를 선택하세요.")

    def _on_image_preview_error(self, message: str) -> None:
        self._log(message)
        QMessageBox.critical(self, "이미지 스캔 실패", message)
        self.status.showMessage(message)

    def _rebuild_current_case(self) -> None:
        if self.case_config is None:
            self.show_case_intake()
            return
        self._start_case_build(self.case_config)

    def _start_case_build(self, case_config: CaseConfig) -> None:
        self.case_config = case_config
        self._show_progress_dialog("사건 분석 구성 중", 100)
        worker = CaseBuildWorker(case_config)
        worker.log_msg.connect(self._log)
        worker.progress.connect(self._on_build_progress)
        worker.done.connect(self._on_case_built)
        worker.error.connect(self._on_case_build_error)
        worker.finished.connect(self._cleanup_finished_worker)
        self._workers.append(worker)
        worker.start()
        self.status.showMessage("사건 분석을 시작했습니다...")

    def _on_build_progress(self, value: int, message: str) -> None:
        if self._progress_dialog is not None:
            self._progress_dialog.set_message(message)
            self._progress_dialog.set_progress(value)
        self.status.showMessage(message)

    def _on_case_built(self, result: dict) -> None:
        self.handler = result["handler"]
        self.artifact_cache = result["artifact_cache"]
        self.timeline_entries = result["timeline"]
        self.risk_result = result["risk_result"]
        self.case_config = result["case_config"]
        self._populate_case_views()
        self._save_recent_case(self.case_config.case_output_dir, self.case_config.case_output_name or self.case_config.case_name)
        self.stack.setCurrentWidget(self.analysis_page)
        self._set_work_mode()
        self.rebuild_action.setVisible(True)
        self._finish_progress_dialog("사건 분석 준비 완료")
        self.status.showMessage("사건 분석이 완료되었습니다.")

    def _on_case_build_error(self, message: str) -> None:
        self._log(message)
        self._finish_progress_dialog(message)
        QMessageBox.critical(self, "사건 분석 실패", message)
        self.status.showMessage(message)

    def _cleanup_finished_worker(self) -> None:
        worker = self.sender()
        if worker in self._workers:
            self._workers.remove(worker)

    def _populate_case_views(self) -> None:
        config = self.case_config
        header_parts = [part for part in [config.case_number, config.case_name] if part]
        self.case_header.setText("  |  ".join(header_parts) if header_parts else "이름 없는 사건")
        self.case_summary.setText(
            f"조사자: {config.investigator or '미지정'}  |  "
            f"이미지: {os.path.basename(config.image_path)}  |  "
            f"파티션: {len(config.partition_offsets)}  |  "
            f"선택 아티팩트: {len(config.artifact_ids)}  |  "
            f"저장 위치: {os.path.basename(config.case_output_dir) if config.case_output_dir else '저장 전'}"
        )
        self.overview_text.setHtml(self._render_case_overview_html())
        self.file_system_tab.set_handler(self.handler)
        self._timeline_loaded = False
        self.timeline_widget.set_events([])
        self.risk_dashboard.set_result(self.risk_result)
        self._populate_artifact_list()

    def _on_result_tab_changed(self, index: int) -> None:
        if index == getattr(self, "timeline_tab_index", 2):
            self._ensure_timeline_loaded()

    def _open_timeline_detail_target(self, path: str, _offset: int) -> None:
        if not path:
            self.status.showMessage("이동할 source path가 없습니다.")
            return
        self.result_tabs.setCurrentIndex(1)  # File System
        ok = self.file_system_tab.open_path(path)
        if ok:
            self.status.showMessage(f"파일 시스템 경로로 이동: {path}")
        else:
            self.status.showMessage(f"파일 시스템에서 경로를 찾지 못함: {path}")

    def _ensure_timeline_loaded(self) -> None:
        if self._timeline_loaded:
            return
        if not self.timeline_entries and self._timeline_file_path:
            self.status.showMessage("타임라인 파일을 읽는 중입니다...")
            QApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                with open(self._timeline_file_path, "r", encoding="utf-8") as stream:
                    loaded = json.load(stream)
                self.timeline_entries = self._restore_timeline_datetimes(loaded if isinstance(loaded, list) else [])
            except Exception as exc:
                self.timeline_entries = []
                self.status.showMessage(f"타임라인 파일 로드 실패: {exc}")
                return
            finally:
                QApplication.restoreOverrideCursor()
        self.status.showMessage("타임라인 데이터를 불러오는 중입니다...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.timeline_widget.set_events(self.timeline_entries)
            self._timeline_loaded = True
            self.status.showMessage("타임라인 로드 완료")
        finally:
            QApplication.restoreOverrideCursor()

    def _render_case_overview_html(self) -> str:
        config = self.case_config
        risk_level = self.risk_result.get("level", "Unknown")
        risk_score = self.risk_result.get("score", 0)
        triggered = len(self.risk_result.get("findings", []))
        timeline_count = len(self.timeline_entries)
        artifact_count = len(config.artifact_ids)
        partition_labels = self._selected_partition_labels()
        artifact_labels = [ARTIFACT_INDEX[artifact_id]["label"] for artifact_id in config.artifact_ids]
        top_findings = self.risk_result.get("findings", [])[:5]

        level_color = {
            "Critical": C_RED,
            "High": C_AMBER,
            "Medium": C_BLUE,
            "Low": C_GREEN,
        }.get(risk_level, C_TEXT)

        def card(title: str, value: str, accent: str = C_TEXT) -> str:
            return (
                f"<div style='display:inline-block; width:23%; min-width:180px; margin-right:1%; "
                f"background:{C_PANEL}; border:1px solid {C_BORDER}; border-radius:10px; padding:14px;'>"
                f"<div style='color:{C_SUBTEXT}; font-size:10pt; margin-bottom:6px;'>{html.escape(title)}</div>"
                f"<div style='color:{accent}; font-size:20pt; font-weight:700;'>{html.escape(value)}</div>"
                f"</div>"
            )

        def bullet_list(items: list[str], empty_text: str) -> str:
            if not items:
                return f"<div style='color:{C_SUBTEXT};'>{html.escape(empty_text)}</div>"
            rows = "".join(
                f"<li style='margin:4px 0;'>{html.escape(item)}</li>"
                for item in items
            )
            return f"<ul style='margin:8px 0 0 18px; padding:0;'>{rows}</ul>"

        def kv_row(label: str, value: str) -> str:
            return (
                "<tr>"
                f"<td style='width:180px; padding:8px 10px; color:{C_SUBTEXT}; "
                "font-weight:600; vertical-align:top;'>"
                f"{html.escape(label)}</td>"
                f"<td style='padding:8px 10px; color:{C_TEXT};'>{value}</td>"
                "</tr>"
            )

        findings_html = "".join(
            (
                f"<li style='margin:6px 0;'>"
                f"<span style='font-weight:700; color:{C_TEXT};'>{html.escape(finding['name'])}</span> "
                f"<span style='color:{C_SUBTEXT};'>({html.escape(finding['severity'])}, +{finding['score']})</span>"
                f"<div style='color:{C_SUBTEXT}; margin-top:2px;'>{html.escape(finding.get('detail', ''))}</div>"
                f"</li>"
            )
            for finding in top_findings
        )
        if not findings_html:
            findings_html = f"<div style='color:{C_SUBTEXT};'>탐지된 규칙이 없습니다.</div>"
        else:
            findings_html = f"<ul style='margin:8px 0 0 18px; padding:0;'>{findings_html}</ul>"

        return f"""
        <div style="font-family:'Malgun Gothic'; color:{C_TEXT}; padding:8px 10px 16px 10px;">
          <div style="margin-bottom:16px;">
            {card("위험도", risk_level, level_color)}
            {card("위험 점수", str(risk_score))}
            {card("타임라인 이벤트", f"{timeline_count:,}")}
            {card("탐지 규칙", str(triggered))}
          </div>

          <div style="background:{C_PANEL}; border:1px solid {C_BORDER}; border-radius:10px; padding:14px; margin-bottom:12px;">
            <div style="font-size:12pt; font-weight:700; color:{C_BLUE}; margin-bottom:10px;">사건 개요</div>
            <table style="width:100%; border-collapse:collapse;">
              {kv_row("사건 번호", html.escape(config.case_number or "미입력"))}
              {kv_row("사건명", html.escape(config.case_name or "이름 없는 사건"))}
              {kv_row("결과 이름", html.escape(config.case_output_name or "미입력"))}
              {kv_row("조사자", html.escape(config.investigator or "미지정"))}
              {kv_row("증거 이미지", f"<span style='font-family:Malgun Gothic, sans-serif;'>{html.escape(config.image_path)}</span>")}
              {kv_row("저장 경로", f"<span style='font-family:Malgun Gothic, sans-serif;'>{html.escape(config.case_output_dir or config.case_storage_dir or '미설정')}</span>")}
            </table>
          </div>

          <div style="background:{C_PANEL}; border:1px solid {C_BORDER}; border-radius:10px; padding:14px; margin-bottom:12px;">
            <div style="font-size:12pt; font-weight:700; color:{C_BLUE}; margin-bottom:10px;">분석 범위</div>
            <table style="width:100%; border-collapse:collapse;">
              {kv_row("선택 파티션", bullet_list(partition_labels, "파티션 정보가 없습니다."))}
              {kv_row("선택 아티팩트", bullet_list(artifact_labels, "선택된 아티팩트가 없습니다."))}
              {kv_row("아티팩트 개수", html.escape(str(artifact_count)))}
            </table>
          </div>

          <div style="background:{C_PANEL}; border:1px solid {C_BORDER}; border-radius:10px; padding:14px;">
            <div style="font-size:12pt; font-weight:700; color:{C_BLUE}; margin-bottom:10px;">주요 위험 탐지</div>
            {findings_html}
          </div>
        </div>
        """

    def _selected_partition_labels(self) -> list[str]:
        if not self.handler:
            return [str(offset) for offset in self.case_config.partition_offsets]
        labels = []
        selected = set(self.case_config.partition_offsets)
        for volume in getattr(self.handler, "volumes", []):
            offset = int(volume.get("offset", 0))
            if offset not in selected:
                continue
            desc = volume.get("desc", "Unknown Volume")
            labels.append(f"{desc} (offset {offset})")
        if labels:
            return labels
        return [f"Offset {offset}" for offset in self.case_config.partition_offsets]

    def _populate_artifact_list(self) -> None:
        self.artifact_list.clear()
        for artifact_id in self.case_config.artifact_ids:
            label = ARTIFACT_INDEX[artifact_id]["label"]
            cached_entries = self.artifact_cache.get(artifact_id)
            if isinstance(cached_entries, list):
                count = len(cached_entries)
                count_text = str(count)
            elif artifact_id in self._artifact_file_map:
                count_text = "Loading"
            else:
                count_text = "0"
            badge = self._artifact_risk_badge(artifact_id)
            item = QListWidgetItem(f"{label} ({count_text})  [{badge}]")
            item.setData(Qt.UserRole, artifact_id)
            self.artifact_list.addItem(item)
        if self.artifact_list.count():
            self.artifact_list.setCurrentRow(0)

    def _load_artifact_entries(self, artifact_id: str) -> list:
        cached = self.artifact_cache.get(artifact_id)
        if isinstance(cached, list):
            return cached
        path = self._artifact_file_map.get(artifact_id, "")
        if not path:
            self.artifact_cache[artifact_id] = []
            return []
        try:
            with open(path, "r", encoding="utf-8") as stream:
                data = json.load(stream)
            entries = data if isinstance(data, list) else []
        except Exception as exc:
            self._log(f"[WARN] 아티팩트 로드 실패: {artifact_id} -> {exc}")
            entries = []
        self.artifact_cache[artifact_id] = entries
        return entries

    def _artifact_risk_badge(self, artifact_id: str) -> str:
        findings = self.risk_result.get("findings", []) if isinstance(self.risk_result, dict) else []
        sev_score = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        best = 0
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            related = finding.get("evidence_artifact_ids") or []
            if artifact_id in related:
                sev = str(finding.get("severity") or "Low")
                best = max(best, sev_score.get(sev, 1))
        if best == 4:
            return "Critical"
        if best == 3:
            return "High"
        if best == 2:
            return "Medium"
        if best == 1:
            return "Low"
        return "Info"

    def _format_event_time(self, value) -> str:
        if isinstance(value, datetime):
            ts = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
            return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if value is None:
            return "-"
        return str(value)

    def _to_detail_lines(self, entry: dict) -> list[tuple[str, str]]:
        common_keys = [
            ("행위", "action"),
            ("대상", "target"),
            ("요약", "summary"),
            ("경로", "path"),
            ("원본 경로", "source_path"),
            ("파일 오프셋", "file_offset"),
            ("아티팩트 유형", "artifact_type"),
            ("출처", "source"),
            ("생성 시각", "created_time"),
            ("수정 시각", "modified_time"),
            ("접근 시각", "accessed_time"),
            ("변경 시각", "changed_time"),
            ("삭제 여부", "is_deleted"),
            ("설명", "description"),
            ("상세", "detail"),
        ]
        lnk_keys = [
            ("원본 파일 경로", "target_path"),
            ("볼륨 시리얼", "volume_serial"),
            ("드라이브 유형", "drive_type"),
            ("파일 크기(바이트)", "file_size"),
            ("ShowCommand", "show_command"),
            ("NetBIOS", "netbios_name"),
            ("MAC 주소", "mac_address"),
            ("LNK 생성 시각", "lnk_created_time"),
            ("LNK 수정 시각", "lnk_modified_time"),
            ("LNK 접근 시각", "lnk_accessed_time"),
        ]
        eventlog_keys = [
            ("Event ID", "event_id"),
            ("채널", "channel"),
            ("로그명", "log_name"),
            ("Provider", "provider"),
            ("컴퓨터명", "computer"),
            ("계정", "subject_user_name"),
            ("사용자 SID", "subject_user_sid"),
            ("레벨", "level"),
            ("Task", "task"),
            ("Opcode", "opcode"),
            ("키워드", "keywords"),
        ]
        usb_keys = [
            ("장치 인스턴스 ID", "device_instance_id"),
            ("장치명", "friendly_name"),
            ("VID/PID", "vid_pid"),
            ("시리얼", "serial"),
            ("최초 연결 시각", "first_install_time"),
            ("마지막 연결 시각", "last_connected_time"),
            ("드라이브 문자", "drive_letter"),
            ("볼륨 GUID", "volume_guid"),
            ("레지스트리 경로", "registry_path"),
        ]

        artifact_type = str(entry.get("artifact_type") or "").lower()
        source = str(entry.get("source") or "").lower()
        template_keys = common_keys
        if "lnk" in artifact_type or "lnk" in source:
            template_keys = common_keys + lnk_keys
        elif "event" in artifact_type or "event" in source or "evtx" in source:
            template_keys = common_keys + eventlog_keys
        elif "usb" in artifact_type or "usb" in source or "mounteddevices" in source:
            template_keys = common_keys + usb_keys

        rows: list[tuple[str, str]] = []
        for label, key in template_keys:
            if key not in entry:
                continue
            value = entry.get(key)
            if isinstance(value, datetime):
                display = self._format_event_time(value)
            elif value in (None, ""):
                continue
            else:
                display = str(value)
            rows.append((label, display))
        if "timestamp" in entry:
            rows.insert(0, ("이벤트 시각", self._format_event_time(entry.get("timestamp"))))
        return rows

    def _on_artifact_result_changed(self, current, _previous) -> None:
        if current is None:
            self.artifact_event_table.setRowCount(0)
            self.artifact_detail.clear()
            return
        artifact_id = current.data(Qt.UserRole)
        entries = self._load_artifact_entries(artifact_id)
        current.setText(f"{ARTIFACT_INDEX[artifact_id]['label']} ({len(entries)})  [{self._artifact_risk_badge(artifact_id)}]")
        self.artifact_event_table.setRowCount(0)
        row = 0
        for entry in entries:
            if isinstance(entry, dict):
                entry_dict = entry
            elif hasattr(entry, "__dict__"):
                entry_dict = dict(getattr(entry, "__dict__", {}))
            else:
                entry_dict = {"summary": str(entry)}
            self.artifact_event_table.insertRow(row)
            ts = self._format_event_time(entry_dict.get("timestamp"))
            action = str(entry_dict.get("action") or "-")
            target = str(entry_dict.get("target") or entry_dict.get("path") or "-")
            summary = str(entry_dict.get("summary") or entry_dict.get("description") or "-")
            for col, text in enumerate([ts, action, target, summary]):
                cell = QTableWidgetItem(text)
                cell.setData(Qt.UserRole, entry_dict)
                self.artifact_event_table.setItem(row, col, cell)
            row += 1

        if self.artifact_event_table.rowCount() > 0:
            self.artifact_event_table.selectRow(0)
        else:
            self.artifact_detail.setPlainText("선택한 아티팩트에 표시할 이벤트가 없습니다.")

    def _on_artifact_event_selected(self) -> None:
        rows = self.artifact_event_table.selectionModel().selectedRows()
        if not rows:
            self.artifact_detail.clear()
            return
        row = rows[0].row()
        item = self.artifact_event_table.item(row, 0)
        if item is None:
            self.artifact_detail.clear()
            return
        entry = item.data(Qt.UserRole)
        if not isinstance(entry, dict):
            self.artifact_detail.clear()
            return
        lines = ["이벤트 상세 정보", ""]
        for key, value in self._to_detail_lines(entry):
            lines.append(f"{key}: {value}")
        self.artifact_detail.setPlainText("\n".join(lines))

    def _show_progress_dialog(self, title: str, total_steps: int) -> None:
        self._finish_progress_dialog()
        self._progress_dialog = ProgressDialog(title, total_steps=total_steps, parent=self)
        self._progress_dialog.show()
        self._progress_dialog.raise_()
        QApplication.processEvents()

    def _finish_progress_dialog(self, message: Optional[str] = None) -> None:
        if self._progress_dialog is None:
            return
        if message:
            self._progress_dialog.complete(message)
            QApplication.processEvents()
        self._progress_dialog.close()
        self._progress_dialog.deleteLater()
        self._progress_dialog = None

    def _log(self, message: str) -> None:
        if hasattr(self, "log_output"):
            ts = datetime.now().strftime("%H:%M:%S")
            self.log_output.append(f"[{ts}] {message}")

    def closeEvent(self, event) -> None:
        for worker in list(self._workers):
            if worker.isRunning():
                worker.quit()
                worker.wait(2000)
        if self.handler is not None:
            try:
                self.handler.close()
            except Exception:
                pass
        event.accept()
