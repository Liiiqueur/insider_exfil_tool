import os
import sys
import json
import tempfile
import logging
from datetime import datetime, timezone

from PyQt5.QtCore import Qt, QThread, QSize, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QAction,
    QFileDialog,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from image_handler import ImageHandler
from collectors import userassist_collector
from parsers import userassist_parser
from collectors import jumplist_collector
from parsers import jumplist_parser
from collectors import prefetch_collector
from parsers import prefetch_parser
from collectors import outlook_store_collector
from parsers import outlook_store_parser
from collectors import printer_spool_collector
from parsers import printer_spool_parser
from collectors import amcache_collector
from parsers import amcache_parser
from collectors import shellbags_collector
from parsers import shellbags_parser
from collectors import mounteddevices_collector
from parsers import mounteddevices_parser
from collectors import usb_registry_collector
from parsers import usb_registry_parser
from collectors.artifact_utils import cleanup_temp_paths
from parsers.artifact_weights import attach_artifact_weight, get_artifact_weight

logger = logging.getLogger(__name__)

SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "..", ".ui_settings.json")

C_BG = "#f5f7fa"
C_PANEL = "#ffffff"
C_BORDER = "#e1e5ea"
C_HEADER = "#eef2f7"
C_TEXT = "#1f2933"
C_SUBTEXT = "#6b7280"
C_SELECT = "#e6f0ff"
C_BLUE = "#2563eb"
C_AMBER = "#f59e0b"
C_GREEN = "#059669"
C_RED = "#dc2626"
C_PURPLE = "#7c3aed"

ARTIFACT_REGISTRY = [
    {"id": "userassist", "label": "UserAssist", "description": "NTUSER.DAT UserAssist 실행 흔적", "color": C_BLUE},
    {"id": "jumplist", "label": "Jumplist", "description": "최근 사용 파일/프로그램 목록", "color": C_PURPLE},
    {"id": "prefetch", "label": "Prefetch", "description": "프로그램 실행 캐시", "color": C_GREEN},
    {"id": "amcache", "label": "Amcache", "description": "응용 프로그램 인벤토리/실행 흔적", "color": C_AMBER},
    {"id": "shellbags", "label": "Shellbags", "description": "탐색기 폴더 열람 흔적", "color": C_BLUE},
    {"id": "mounteddevices", "label": "MountedDevices", "description": "드라이브 문자/볼륨 매핑 정보", "color": C_PURPLE},
    {"id": "usb_registry", "label": "USB Registry", "description": "USBSTOR / Enum\\USB 장치 흔적", "color": C_RED},
    {"id": "outlook_store", "label": "Outlook OST/PST", "description": "Outlook 메일 저장소 파일", "color": C_GREEN},
    {"id": "printer_spool", "label": "Printer Spool", "description": "프린터 스풀 로그/작업 파일", "color": C_AMBER},
]
ARTIFACT_INDEX = {item["id"]: item for item in ARTIFACT_REGISTRY}

# NOTE: Re-declare the artifact registry with ASCII-safe descriptions for stable UI text.
ARTIFACT_REGISTRY = [
    {"id": "userassist", "label": "UserAssist", "description": "NTUSER.DAT UserAssist execution evidence", "color": C_BLUE},
    {"id": "jumplist", "label": "Jumplist", "description": "Recent file and application history", "color": C_PURPLE},
    {"id": "prefetch", "label": "Prefetch", "description": "Program execution cache", "color": C_GREEN},
    {"id": "amcache", "label": "Amcache", "description": "Application inventory and execution traces", "color": C_AMBER},
    {"id": "shellbags", "label": "Shellbags", "description": "Explorer folder access traces", "color": C_BLUE},
    {"id": "mounteddevices", "label": "MountedDevices", "description": "Drive letter and volume mapping data", "color": C_PURPLE},
    {"id": "usb_registry", "label": "USB Registry", "description": "USBSTOR and Enum\\USB device traces", "color": C_RED},
    {"id": "outlook_store", "label": "Outlook OST/PST", "description": "Outlook mailbox store files", "color": C_GREEN},
    {"id": "printer_spool", "label": "Printer Spool", "description": "Printer spool job files", "color": C_AMBER},
]
ARTIFACT_INDEX = {item["id"]: item for item in ARTIFACT_REGISTRY}


def _cleanup_entries(entries: list[dict]) -> None:
    cleanup_temp_paths(entries)


def _run_userassist(handler: ImageHandler, log_cb) -> list[dict]:
    all_entries = []
    for vol in handler.volumes:
        fs = vol["fs"]
        log_cb(f"[INFO] [{vol['desc']}] scanning NTUSER.DAT")
        for hive in handler.find_ntuser_dat(fs):
            raw_data = handler.read_file(fs, hive["inode"], 50 * 1024 * 1024)
            if not raw_data:
                continue
            with tempfile.NamedTemporaryFile(suffix="_NTUSER.DAT", delete=False) as tmp:
                tmp.write(raw_data)
                tmp_path = tmp.name
            try:
                raw = userassist_collector.collect(tmp_path)
                parsed = userassist_parser.parse(raw)
                all_entries.extend(attach_artifact_weight(entry, "userassist") for entry in parsed)
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
    return all_entries


def _run_jumplist(handler: ImageHandler, log_cb) -> list[dict]:
    collected = []
    for vol in handler.volumes:
        fs = vol["fs"]
        log_cb(f"[INFO] [{vol['desc']}] scanning Jumplist")
        collected.extend(jumplist_collector.collect_from_image(handler, fs))
    try:
        parsed = jumplist_parser.parse(collected)
        return [attach_artifact_weight(entry, "jumplist") for entry in parsed]
    finally:
        _cleanup_entries(collected)


def _run_module(handler: ImageHandler, log_cb, collector_module, parser_module) -> list[dict]:
    collected = []
    for vol in handler.volumes:
        fs = vol["fs"]
        log_cb(f"[INFO] [{vol['desc']}] collecting {collector_module.__name__.split('.')[-1]}")
        collected.extend(collector_module.collect_from_image(handler, fs))
    try:
        return parser_module.parse(collected)
    finally:
        _cleanup_entries(collected)


ARTIFACT_RUNNERS = {
    "userassist": lambda handler, log_cb: _run_userassist(handler, log_cb),
    "jumplist": lambda handler, log_cb: _run_jumplist(handler, log_cb),
    "prefetch": lambda handler, log_cb: _run_module(handler, log_cb, prefetch_collector, prefetch_parser),
    "outlook_store": lambda handler, log_cb: _run_module(handler, log_cb, outlook_store_collector, outlook_store_parser),
    "printer_spool": lambda handler, log_cb: _run_module(handler, log_cb, printer_spool_collector, printer_spool_parser),
    "amcache": lambda handler, log_cb: _run_module(handler, log_cb, amcache_collector, amcache_parser),
    "shellbags": lambda handler, log_cb: _run_module(handler, log_cb, shellbags_collector, shellbags_parser),
    "mounteddevices": lambda handler, log_cb: _run_module(handler, log_cb, mounteddevices_collector, mounteddevices_parser),
    "usb_registry": lambda handler, log_cb: _run_module(handler, log_cb, usb_registry_collector, usb_registry_parser),
}


class LoadImageWorker(QThread):
    done = pyqtSignal(object)
    log_msg = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, path: str):
        super().__init__()
        self.path = path

    def run(self):
        try:
            self.log_msg.emit(f"[INFO] opening image: {self.path}")
            handler = ImageHandler()
            handler.open(self.path)
            if not handler.volumes:
                self.error.emit("[ERROR] no readable volume found")
                return
            self.done.emit(handler)
        except Exception as exc:
            self.error.emit(f"[ERROR] image open failed: {exc}")


class ListDirWorker(QThread):
    done = pyqtSignal(list, object)
    error = pyqtSignal(str)

    def __init__(self, handler, fs, inode, path, tree_item):
        super().__init__()
        self.handler = handler
        self.fs = fs
        self.inode = inode
        self.path = path
        self.tree_item = tree_item

    def run(self):
        try:
            entries = self.handler.list_directory(self.fs, self.inode, self.path)
            self.done.emit(entries, self.tree_item)
        except Exception as exc:
            self.error.emit(f"[ERROR] directory read failed: {exc}")


class ArtifactWorker(QThread):
    done = pyqtSignal(str, list)
    log_msg = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, artifact_id: str, handler: ImageHandler):
        super().__init__()
        self.artifact_id = artifact_id
        self.handler = handler

    def run(self):
        runner = ARTIFACT_RUNNERS.get(self.artifact_id)
        if not runner:
            self.error.emit(f"[ERROR] unsupported artifact: {self.artifact_id}")
            return
        try:
            entries = runner(self.handler, self.log_msg.emit)
            self.log_msg.emit(f"[INFO] {self.artifact_id} parsed: {len(entries)} entries")
            self.done.emit(self.artifact_id, entries)
        except Exception as exc:
            self.error.emit(f"[ERROR] {self.artifact_id} parse failed: {exc}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # NOTE: Status bar controls the global UI scale from a 10pt base size.
        self._base_font_pt = 10
        self._font_scale_percent = self._load_font_scale_percent()
        self.setWindowTitle("Insider Exfiltration Tool")
        self.setGeometry(100, 100, 1500, 900)
        self.setMinimumSize(1100, 650)

        self._handler = None
        self._workers = []
        self._item_meta = {}
        self._table_entries = []
        self._table_fs = None
        self._artifact_cache = {}
        self._current_aid = None

        self._init_ui()
        self._apply_dynamic_fonts()
        self._apply_style()

    def _init_ui(self):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)

        act_open = QAction("Open Image", self)
        act_open.triggered.connect(self._open_image)

        self.act_export = QAction("Export Result", self)
        self.act_export.setEnabled(False)
        self.act_export.triggered.connect(self._export_results)

        toolbar.addAction(act_open)
        toolbar.addSeparator()
        toolbar.addAction(self.act_export)

        main_split = QSplitter(Qt.Horizontal)
        main_split.addWidget(self._make_evidence_tree())
        main_split.addWidget(self._make_file_browser())
        main_split.addWidget(self._make_artifact_panel())
        main_split.setSizes([250, 700, 500])
        main_split.setStretchFactor(1, 2)

        log_panel = QWidget()
        log_layout = QVBoxLayout(log_panel)
        log_layout.setContentsMargins(4, 0, 4, 2)
        log_layout.setSpacing(0)
        log_label = QLabel("  Log")
        log_label.setFixedHeight(20)
        log_label.setObjectName("log_header")
        log_layout.addWidget(log_label)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFixedHeight(110)
        self.log_output.setFont(QFont("Consolas", self._scaled_pt(9)))
        log_layout.addWidget(self.log_output)

        root = QVBoxLayout()
        root.setContentsMargins(4, 4, 4, 4)
        root.setSpacing(4)
        root.addWidget(main_split, stretch=1)
        root.addWidget(log_panel)

        container = QWidget()
        container.setLayout(root)
        self.setCentralWidget(container)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        # NOTE: Keep font size control visible in the bottom-right corner.
        # NOTE: Use explicit down/up buttons so the scale control reads as ▼ 100% ▲.
        self.font_down_btn = QPushButton("▼")
        self.font_down_btn.setObjectName("font_scale_btn")
        self.font_down_btn.setFixedWidth(28)
        self.font_down_btn.setFlat(True)
        self.font_down_btn.setText("\u25BC")
        self.font_down_btn.clicked.connect(lambda: self._change_font_scale(-10))
        self.status.addPermanentWidget(self.font_down_btn)

        self.font_scale_label = QLabel()
        self.font_scale_label.setObjectName("font_scale_label")
        self.status.addPermanentWidget(self.font_scale_label)

        self.font_up_btn = QPushButton("▲")
        self.font_up_btn.setObjectName("font_scale_btn")
        self.font_up_btn.setFixedWidth(28)
        self.font_up_btn.setFlat(True)
        self.font_up_btn.setText("\u25B2")
        self.font_up_btn.clicked.connect(lambda: self._change_font_scale(10))
        self.status.addPermanentWidget(self.font_up_btn)
        self.status.showMessage("Open a forensic image to start.")

    def _make_evidence_tree(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        label = QLabel("  Evidence Tree")
        label.setFixedHeight(28)
        label.setObjectName("panel_header")
        layout.addWidget(label)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemExpanded.connect(self._on_tree_expanded)
        self.tree.itemClicked.connect(self._on_tree_clicked)
        layout.addWidget(self.tree)
        return panel

    def _make_file_browser(self) -> QWidget:
        file_panel = QWidget()
        file_layout = QVBoxLayout(file_panel)
        file_layout.setContentsMargins(0, 0, 0, 0)
        file_layout.setSpacing(0)

        label = QLabel("  File Browser")
        label.setFixedHeight(28)
        label.setObjectName("panel_header")
        file_layout.addWidget(label)

        self.file_table = QTableWidget()
        self.file_table.setColumnCount(4)
        self.file_table.setHorizontalHeaderLabels(["Name", "Size", "Type", "Inode"])
        self.file_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.file_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.file_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.file_table.verticalHeader().setVisible(False)
        self.file_table.itemClicked.connect(self._on_file_clicked)
        file_layout.addWidget(self.file_table)

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Consolas", self._scaled_pt(10)))

        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.text_view.setFont(QFont("Consolas", self._scaled_pt(10)))

        self.meta_view = QTextEdit()
        self.meta_view.setReadOnly(True)
        self.meta_view.setFont(QFont("Consolas", self._scaled_pt(10)))

        viewer_tabs = QTabWidget()
        viewer_tabs.setObjectName("viewer_tabs")
        viewer_tabs.addTab(self.hex_view, "Hex")
        viewer_tabs.addTab(self.text_view, "Text")
        viewer_tabs.addTab(self.meta_view, "Metadata")

        split = QSplitter(Qt.Vertical)
        split.addWidget(file_panel)
        split.addWidget(viewer_tabs)
        split.setSizes([400, 260])
        return split

    def _make_artifact_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        label = QLabel("  Artifacts")
        label.setFixedHeight(28)
        label.setObjectName("panel_header")
        layout.addWidget(label)

        self.artifact_list = QListWidget()
        self.artifact_list.setFixedHeight(len(ARTIFACT_REGISTRY) * 52 + 8)
        self.artifact_list.setSpacing(2)
        for artifact in ARTIFACT_REGISTRY:
            item = QListWidgetItem(f"  {artifact['label']}")
            item.setData(Qt.UserRole, artifact["id"])
            item.setToolTip(artifact["description"])
            self.artifact_list.addItem(item)
        self.artifact_list.itemClicked.connect(self._on_artifact_clicked)
        layout.addWidget(self.artifact_list)

        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setObjectName("divider")
        layout.addWidget(divider)

        info_bar = QWidget()
        info_layout = QHBoxLayout(info_bar)
        info_layout.setContentsMargins(8, 4, 8, 4)
        self.art_title_lbl = QLabel("Select an artifact")
        self.art_title_lbl.setObjectName("art_title")
        info_layout.addWidget(self.art_title_lbl, stretch=1)

        self.run_btn = QPushButton("Run")
        self.run_btn.setObjectName("run_btn")
        self.run_btn.setFixedWidth(72)
        self.run_btn.setEnabled(False)
        self.run_btn.clicked.connect(self._run_selected_artifact)
        info_layout.addWidget(self.run_btn)
        layout.addWidget(info_bar)

        self.result_tabs = QTabWidget()
        self.result_tabs.setObjectName("result_tabs")

        self.result_summary = QTextEdit()
        self.result_summary.setReadOnly(True)
        self.result_summary.setFont(QFont("Consolas", self._scaled_pt(10)))
        self.result_summary.setPlaceholderText("Select an artifact and click Run.")

        self.result_raw = QTextEdit()
        self.result_raw.setReadOnly(True)
        self.result_raw.setFont(QFont("Consolas", self._scaled_pt(9)))

        self.result_tabs.addTab(self.result_summary, "Summary")
        self.result_tabs.addTab(self.result_raw, "Raw")
        layout.addWidget(self.result_tabs, stretch=1)
        return panel

    def _open_image(self):
        # NOTE: Show raw/dd style images first and keep split .001 segments visible.
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Image",
            "",
            "Disk Images (*.001 *.dd *.raw *.img);;EWF Images (*.E01 *.e01);;All Files (*)",
        )
        if not path:
            return

        self.tree.clear()
        self.file_table.setRowCount(0)
        self.hex_view.clear()
        self.text_view.clear()
        self._item_meta.clear()
        self._artifact_cache.clear()
        self.result_summary.clear()
        self.result_raw.clear()
        self.act_export.setEnabled(False)

        worker = LoadImageWorker(path)
        worker.log_msg.connect(self._log)
        worker.done.connect(self._on_image_loaded)
        worker.error.connect(self._on_error)
        self._keep(worker)
        worker.start()

    def _on_image_loaded(self, handler):
        self._handler = handler
        self.status.showMessage(f"Image loaded: {os.path.basename(handler.image_path)}")
        self._log(f"[INFO] image loaded with {len(handler.volumes)} volume(s)")

        root_item = QTreeWidgetItem([f"[IMG] {os.path.basename(handler.image_path)}"])
        root_item.setForeground(0, QColor(C_AMBER))
        self.tree.addTopLevelItem(root_item)

        for vol in handler.volumes:
            vol_item = QTreeWidgetItem([f"[VOL] {vol['desc']}"])
            vol_item.setForeground(0, QColor(C_BLUE))
            self._item_meta[id(vol_item)] = {"fs": vol["fs"], "inode": None, "path": "/", "is_dir": True}
            vol_item.addChild(QTreeWidgetItem(["Loading..."]))
            root_item.addChild(vol_item)

        root_item.setExpanded(True)
        self.run_btn.setEnabled(self._current_aid is not None)

    def _on_tree_expanded(self, item):
        meta = self._item_meta.get(id(item))
        if not meta:
            return
        if item.childCount() == 1 and item.child(0).text(0) == "Loading...":
            item.takeChildren()
            worker = ListDirWorker(self._handler, meta["fs"], meta["inode"], meta["path"], item)
            worker.done.connect(self._on_dir_loaded)
            worker.error.connect(self._on_error)
            self._keep(worker)
            worker.start()

    def _on_dir_loaded(self, entries, parent_item):
        for entry in entries:
            icon = "[DIR]" if entry.is_dir else self._file_icon(entry.name)
            child = QTreeWidgetItem([f"{icon}  {entry.name}"])
            child.setForeground(0, QColor(C_AMBER if entry.is_dir else C_TEXT))
            self._item_meta[id(child)] = {
                "fs": self._item_meta[id(parent_item)]["fs"],
                "inode": entry.inode,
                "path": entry.path,
                "is_dir": entry.is_dir,
            }
            if entry.is_dir:
                child.addChild(QTreeWidgetItem(["Loading..."]))
            parent_item.addChild(child)

    def _on_tree_clicked(self, item):
        meta = self._item_meta.get(id(item))
        if not meta or not meta["is_dir"]:
            return
        worker = ListDirWorker(self._handler, meta["fs"], meta["inode"], meta["path"], item)
        worker.done.connect(self._populate_file_table)
        worker.error.connect(self._on_error)
        self._keep(worker)
        worker.start()

    def _populate_file_table(self, entries, _item=None):
        self._table_entries = entries
        self._table_fs = self._item_meta.get(id(self.tree.currentItem()), {}).get("fs")
        self.file_table.setRowCount(0)

        for row, entry in enumerate(entries):
            self.file_table.insertRow(row)
            cells = [
                QTableWidgetItem(f"{'[DIR]' if entry.is_dir else self._file_icon(entry.name)} {entry.name}"),
                QTableWidgetItem("" if entry.is_dir else self._fmt_size(entry.size)),
                QTableWidgetItem("DIR" if entry.is_dir else self._ext(entry.name)),
                QTableWidgetItem(str(entry.inode)),
            ]
            for col, cell in enumerate(cells):
                cell.setForeground(QColor(C_TEXT))
                self.file_table.setItem(row, col, cell)

    def _on_file_clicked(self, item):
        row = item.row()
        if row >= len(self._table_entries):
            return
        entry = self._table_entries[row]
        if entry.is_dir:
            # NOTE: Allow directory navigation directly from the file browser.
            self._table_entries = self._handler.list_directory(entry._fs, entry.inode, entry.path)
            self._table_fs = entry._fs
            self._populate_file_table(self._table_entries)
            self._show_metadata(entry)
            self.hex_view.clear()
            self.text_view.clear()
            self.status.showMessage(f"{entry.path} (directory)")
            return
        if not self._table_fs:
            return
        data = self._handler.read_file(self._table_fs, entry.inode, max_bytes=64 * 1024)
        self._show_metadata(entry)
        self._show_hex(data)
        self._show_text(data, entry.name)
        self.status.showMessage(f"{entry.path} ({self._fmt_size(entry.size)})")

    def _show_hex(self, data: bytes):
        lines = []
        for index in range(0, min(len(data), 4096), 16):
            chunk = data[index:index + 16]
            hex_part = " ".join(f"{value:02X}" for value in chunk)
            text_part = "".join(chr(value) if 32 <= value < 127 else "." for value in chunk)
            lines.append(f"{index:08X}  {hex_part:<48}  {text_part}")
        self.hex_view.setPlainText("\n".join(lines))

    def _show_text(self, data: bytes, name: str):
        ext = os.path.splitext(name)[1].lower()
        text_like_exts = {
            ".txt", ".log", ".csv", ".json", ".xml", ".ini", ".cfg", ".reg",
            ".py", ".md", ".html", ".htm", ".css", ".js", ".ps1", ".bat",
        }
        if ext in {".pdf", ".ppt", ".pptx", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar"}:
            self.text_view.setPlainText(
                "Text preview is not useful for this file type.\n\n"
                "Recommended direction:\n"
                "- Keep Metadata as the default quick view.\n"
                "- Show Hex only for low-level inspection.\n"
                "- Add a dedicated document parser or external preview later if needed."
            )
            return
        if ext not in text_like_exts and b"\x00" in data[:2048]:
            self.text_view.setPlainText(
                "This file looks binary, so a text preview is intentionally suppressed.\n"
                "Use Metadata for quick triage or Hex for raw inspection."
            )
            return
        self.text_view.setPlainText(data.decode("utf-8", errors="replace")[:8192])

    def _show_metadata(self, entry):
        lines = [
            f"Path: {entry.path}",
            f"Name: {entry.name}",
            f"Type: {'Directory' if entry.is_dir else self._ext(entry.name)}",
            f"Size: {self._fmt_size(entry.size)}",
            f"Inode: {entry.inode}",
            f"Created: {self._fmt_dt(entry.created_time)}",
            f"Modified: {self._fmt_dt(entry.modified_time)}",
            f"Accessed: {self._fmt_dt(entry.accessed_time)}",
            f"Changed: {self._fmt_dt(entry.changed_time)}",
        ]
        self.meta_view.setPlainText("\n".join(lines))

    def _on_artifact_clicked(self, item: QListWidgetItem):
        aid = item.data(Qt.UserRole)
        self._current_aid = aid
        artifact = ARTIFACT_INDEX[aid]
        self.art_title_lbl.setText(artifact["label"])
        self.run_btn.setEnabled(self._handler is not None)

        if aid in self._artifact_cache:
            self._display_artifact(aid, self._artifact_cache[aid])
        else:
            weight = get_artifact_weight(aid)
            self.result_summary.setPlainText(
                f"{artifact['label']}\n\n"
                f"{artifact['description']}\n\n"
                f"Weight: frequency={weight['frequency']}, "
                f"probative={weight['probative']}, "
                f"tamper_resistance={weight['tamper_resistance']}, "
                f"total={weight['total']}"
            )
            self.result_raw.clear()

    def _run_selected_artifact(self):
        if not self._handler or not self._current_aid:
            return

        self.run_btn.setEnabled(False)
        self.run_btn.setText("...")
        self.result_summary.setPlainText("Collecting and parsing...")
        self.result_raw.clear()

        worker = ArtifactWorker(self._current_aid, self._handler)
        worker.log_msg.connect(self._log)
        worker.done.connect(self._on_artifact_done)
        worker.error.connect(self._on_artifact_error)
        worker.finished.connect(lambda: (self.run_btn.setEnabled(True), self.run_btn.setText("Run")))
        self._keep(worker)
        worker.start()

    def _on_artifact_done(self, aid: str, entries: list):
        self._artifact_cache[aid] = entries
        self._display_artifact(aid, entries)
        self.act_export.setEnabled(bool(entries))

    def _on_artifact_error(self, msg: str):
        self._log(msg)
        self.result_summary.setPlainText(msg)

    def _display_artifact(self, aid: str, entries: list):
        if not entries:
            self.result_summary.setPlainText("No entries were collected.")
            self.result_raw.clear()
            return

        summary = self._format_entries(aid, entries)
        raw = json.dumps(entries, default=self._json_default, ensure_ascii=False, indent=2)
        self.result_summary.setPlainText(summary)
        self.result_raw.setPlainText(raw)
        self.result_tabs.setCurrentIndex(0)
        self.status.showMessage(f"{aid}: {len(entries)} entries")

    def _format_entries(self, aid: str, entries: list) -> str:
        artifact = ARTIFACT_INDEX[aid]
        weight = get_artifact_weight(aid)
        lines = [
            "=" * 72,
            f"{artifact['label']}  total={len(entries)}",
            f"weight: frequency={weight['frequency']} / probative={weight['probative']} / "
            f"tamper_resistance={weight['tamper_resistance']} / total={weight['total']}",
            "=" * 72,
            "",
        ]

        for entry in entries[:50]:
            lines.extend(self._artifact_entry_lines(aid, entry))
            lines.append("")

        if len(entries) > 50:
            lines.append(f"... truncated {len(entries) - 50} additional entries")
        return "\n".join(lines)

    def _artifact_entry_lines(self, aid: str, entry: dict) -> list[str]:
        if aid == "userassist":
            return [
                f"[{entry.get('guid_type')}] {entry.get('name') or '(no name)'}",
                f"  user={entry.get('username', '?')} run_count={entry.get('run_count')} last_run={self._fmt_dt(entry.get('last_run_time'))}",
            ]
        if aid == "jumplist":
            return [
                f"[{entry.get('category')}] {entry.get('appname')} ({entry.get('appid')})",
                f"  path={entry.get('target_path') or entry.get('name')} access_count={entry.get('access_count')} last_access={self._fmt_dt(entry.get('access_time'))}",
            ]
        if aid == "prefetch":
            return [
                f"{entry.get('executable_name')} ({entry.get('filename')})",
                f"  run_count={entry.get('run_count')} version={entry.get('format_version')} last_run={self._fmt_dt(entry.get('last_run_time'))}",
            ]
        if aid == "amcache":
            return [
                f"{entry.get('program_name')}",
                f"  path={entry.get('file_path')} sha1={entry.get('sha1')} key_time={self._fmt_dt(entry.get('key_timestamp'))}",
            ]
        if aid == "shellbags":
            return [
                f"{entry.get('shell_path')}",
                f"  user={entry.get('username')} key_time={self._fmt_dt(entry.get('last_written_time'))}",
            ]
        if aid == "mounteddevices":
            return [
                f"{entry.get('value_name')} [{entry.get('mapping_type')}]",
                f"  data={entry.get('decoded_data')}",
            ]
        if aid == "usb_registry":
            return [
                f"{entry.get('friendly_name') or entry.get('device_id')}",
                f"  serial={entry.get('serial_number')} class={entry.get('device_class')} first_seen={self._fmt_dt(entry.get('first_seen_time'))}",
            ]
        if aid == "outlook_store":
            return [
                f"{entry.get('filename')} ({entry.get('store_type')})",
                f"  user={entry.get('username')} messages={entry.get('message_count')} last_message={self._fmt_dt(entry.get('last_message_time'))}",
            ]
        if aid == "printer_spool":
            return [
                f"{entry.get('document_name')} [{entry.get('job_id')}]",
                f"  printer={entry.get('printer_name')} format={entry.get('spool_format')} size={self._fmt_size(entry.get('size_total', 0))}",
            ]
        return [str(entry)]

    def _export_results(self):
        if not self._current_aid:
            return
        default_name = f"{self._current_aid}_result.txt"
        path, _ = QFileDialog.getSaveFileName(self, "Save Result", default_name, "Text Files (*.txt)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(self.result_summary.toPlainText())
        self._log(f"[INFO] exported result: {path}")

    def _log(self, msg: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_output.append(f"[{timestamp}] {msg}")

    def _on_error(self, msg: str):
        self._log(msg)
        self.status.showMessage(msg)

    def _keep(self, worker):
        self._workers.append(worker)
        worker.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)

    def _change_font_scale(self, delta: int):
        # NOTE: Adjust the persisted scale in fixed 10 percent steps.
        value = max(50, min(200, self._font_scale_percent + delta))
        self._set_font_scale_percent(value)

    def _set_font_scale_percent(self, value: int):
        # NOTE: Re-apply the stylesheet so the whole interface scales together.
        self._font_scale_percent = value
        self._save_font_scale_percent()
        self._apply_dynamic_fonts()
        self._apply_style()

    def _apply_dynamic_fonts(self):
        # NOTE: Widgets with explicit fonts need manual updates when scale changes.
        self.log_output.setFont(QFont("Consolas", self._scaled_pt(9)))
        self.hex_view.setFont(QFont("Consolas", self._scaled_pt(10)))
        self.text_view.setFont(QFont("Consolas", self._scaled_pt(10)))
        self.result_summary.setFont(QFont("Consolas", self._scaled_pt(10)))
        self.result_raw.setFont(QFont("Consolas", self._scaled_pt(9)))
        for index in range(self.artifact_list.count()):
            self.artifact_list.item(index).setFont(QFont("Malgun Gothic", self._scaled_pt(self._base_font_pt)))
        self.font_scale_label.setText(f"{self._font_scale_percent}%")
        self.font_down_btn.setEnabled(self._font_scale_percent > 50)
        self.font_up_btn.setEnabled(self._font_scale_percent < 200)

    def _scaled_pt(self, base_pt: int) -> int:
        return max(int(round(base_pt * self._font_scale_percent / 100)), 1)

    def _load_font_scale_percent(self) -> int:
        # NOTE: Load persisted UI scale if the settings file is present.
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as stream:
                data = json.load(stream)
            value = int(data.get("font_scale_percent", 100))
            return max(50, min(200, value))
        except Exception:
            return 100

    def _save_font_scale_percent(self) -> None:
        # NOTE: Save the UI scale so the next run restores the same value.
        try:
            with open(SETTINGS_PATH, "w", encoding="utf-8") as stream:
                json.dump({"font_scale_percent": self._font_scale_percent}, stream, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.debug("failed to save ui settings: %s", exc)

    @staticmethod
    def _fmt_size(size):
        if size is None:
            return "?"
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    @staticmethod
    def _ext(name):
        ext = os.path.splitext(name)[1].lower()
        return ext.lstrip(".").upper() if ext else "FILE"

    @staticmethod
    def _fmt_dt(value):
        if not value:
            return "N/A"
        if getattr(value, "tzinfo", None) is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    @staticmethod
    def _json_default(value):
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).isoformat()
        return str(value)

    @staticmethod
    def _file_icon(name):
        ext = os.path.splitext(name)[1].lower()
        icons = {
            ".exe": "[EXE]",
            ".dll": "[DLL]",
            ".sys": "[SYS]",
            ".txt": "[TXT]",
            ".log": "[LOG]",
            ".csv": "[CSV]",
            ".dat": "[DAT]",
            ".db": "[DB]",
            ".sqlite": "[DB]",
            ".lnk": "[LNK]",
            ".pf": "[PF]",
            ".jpg": "[IMG]",
            ".png": "[IMG]",
            ".zip": "[ZIP]",
            ".rar": "[ZIP]",
        }
        return icons.get(ext, "[FILE]")

    def _apply_style(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {C_BG};
                color: {C_TEXT};
                font-family: 'Malgun Gothic', 'Segoe UI', sans-serif;
                font-size: {self._scaled_pt(self._base_font_pt)}pt;
            }}
            QToolBar {{
                background-color: {C_HEADER};
                border-bottom: 1px solid {C_BORDER};
                spacing: 4px;
                padding: 4px 10px;
            }}
            QToolBar QToolButton {{
                background: transparent;
                color: {C_TEXT};
                padding: 5px 14px;
                border-radius: 5px;
                font-size: {self._scaled_pt(self._base_font_pt)}pt;
            }}
            QToolBar QToolButton:hover {{
                background: {C_SELECT};
                color: {C_BLUE};
            }}
            QLabel#panel_header {{
                background: {C_HEADER};
                color: {C_BLUE};
                font-weight: bold;
                font-size: {max(self._scaled_pt(self._base_font_pt - 1), 8)}pt;
                padding-left: 8px;
                border-bottom: 1px solid {C_BORDER};
            }}
            QLabel#log_header {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                font-size: {max(self._scaled_pt(self._base_font_pt - 2), 8)}pt;
                padding-left: 8px;
            }}
            QLabel#art_title {{
                font-weight: bold;
                font-size: {self._scaled_pt(self._base_font_pt)}pt;
                color: {C_TEXT};
            }}
            QLabel#font_scale_label {{
                color: {C_TEXT};
                padding: 0 4px;
                min-width: 44px;
            }}
            QTreeWidget {{
                background: {C_PANEL};
                border: none;
                border-right: 1px solid {C_BORDER};
            }}
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {{
                background: {C_SELECT};
                color: {C_BLUE};
            }}
            QTableWidget {{
                background: {C_PANEL};
                border: none;
                gridline-color: {C_BORDER};
            }}
            QHeaderView::section {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                border: none;
                border-bottom: 1px solid {C_BORDER};
                border-right: 1px solid {C_BORDER};
                padding: 4px 8px;
                font-size: {max(self._scaled_pt(self._base_font_pt - 1), 8)}pt;
            }}
            QListWidget {{
                background: {C_PANEL};
                border: none;
                border-bottom: 1px solid {C_BORDER};
                outline: none;
            }}
            QListWidget::item {{
                padding: 10px 6px;
                border-bottom: 1px solid {C_BORDER};
                color: {C_TEXT};
            }}
            QPushButton#run_btn {{
                background: {C_BLUE};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-weight: bold;
                font-size: {max(self._scaled_pt(self._base_font_pt - 1), 8)}pt;
            }}
            QPushButton#run_btn:hover {{
                background: #1d4ed8;
            }}
            QPushButton#run_btn:disabled {{
                background: {C_SUBTEXT};
            }}
            QPushButton#font_scale_btn {{
                background: transparent;
                color: {C_TEXT};
                border: none;
                padding: 0 2px;
                min-width: 20px;
            }}
            QPushButton#font_scale_btn:hover {{
                color: {C_BLUE};
            }}
            QPushButton#font_scale_btn:pressed {{
                color: #1d4ed8;
            }}
            QPushButton#font_scale_btn:disabled {{
                color: {C_SUBTEXT};
            }}
            QTabWidget#viewer_tabs::pane,
            QTabWidget#result_tabs::pane {{
                border: 1px solid {C_BORDER};
                background: {C_PANEL};
            }}
            QTabBar::tab {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                padding: 5px 16px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background: {C_PANEL};
                color: {C_BLUE};
                border-bottom: 2px solid {C_BLUE};
            }}
            QTextEdit {{
                background: {C_PANEL};
                color: {C_TEXT};
                border: none;
                selection-background-color: {C_SELECT};
            }}
            QFrame#divider {{
                color: {C_BORDER};
            }}
            QStatusBar {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                font-size: {max(self._scaled_pt(self._base_font_pt - 1), 8)}pt;
            }}
            QSplitter::handle {{
                background: {C_BORDER};
                width: 1px;
                height: 1px;
            }}
        """)
