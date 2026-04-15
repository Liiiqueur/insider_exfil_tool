import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timezone

from PyQt5.QtCore import QSize, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QKeySequence
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QAction,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolTip,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from PyQt5.QtWidgets import QApplication

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from image_handler import ImageHandler
from collectors import (
    browser_artifacts_collector,
    eventlog_collector,
    filesystem_collector,
    jumplist_collector,
    lnk_collector,
    mounteddevices_collector,
    recentdocs_collector,
    shellbags_collector,
    userassist_collector,
)
from collectors.artifact_utils import cleanup_temp_paths
from parsers import (
    browser_artifacts_parser,
    eventlog_parser,
    filesystem_parser,
    jumplist_parser,
    lnk_parser,
    mounteddevices_parser,
    recentdocs_parser,
    shellbags_parser,
    userassist_parser,
)
from parsers.artifact_weights import attach_artifact_weight

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
    {"id": "filesystem", "label": "$MFT, $J", "description": "NTFS metadata reconstructed from $MFT plus raw $J collection", "color": C_AMBER},
    {"id": "lnk", "label": "LNK", "description": "Shortcut files from Recent, Desktop, and Start Menu", "color": C_PURPLE},
    {"id": "eventlog", "label": "Event Log", "description": "Security and device event logs related to file access, process creation, logon, and USB activity", "color": C_RED},
    {"id": "recentdocs", "label": "RecentDocs", "description": "RecentDocs registry traces from NTUSER.DAT", "color": C_BLUE},
    {"id": "browser_artifacts", "label": "Browser History", "description": "Browser history, downloads, and cookies from Chrome, Edge, and Firefox", "color": C_GREEN},
    {"id": "userassist", "label": "UserAssist", "description": "NTUSER.DAT UserAssist execution evidence", "color": C_BLUE},
    {"id": "jumplist", "label": "Jumplist", "description": "Recent file and application history", "color": C_PURPLE},
    {"id": "shellbags", "label": "Shellbags", "description": "Explorer folder access traces", "color": C_BLUE},
    {"id": "mounteddevices", "label": "MountedDevices", "description": "Drive letter and volume mapping data", "color": C_PURPLE},
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
    "filesystem": lambda handler, log_cb: _run_module(handler, log_cb, filesystem_collector, filesystem_parser),
    "lnk": lambda handler, log_cb: _run_module(handler, log_cb, lnk_collector, lnk_parser),
    "eventlog": lambda handler, log_cb: _run_module(handler, log_cb, eventlog_collector, eventlog_parser),
    "recentdocs": lambda handler, log_cb: _run_module(handler, log_cb, recentdocs_collector, recentdocs_parser),
    "browser_artifacts": lambda handler, log_cb: _run_module(handler, log_cb, browser_artifacts_collector, browser_artifacts_parser),
    "userassist": lambda handler, log_cb: _run_userassist(handler, log_cb),
    "jumplist": lambda handler, log_cb: _run_jumplist(handler, log_cb),
    "shellbags": lambda handler, log_cb: _run_module(handler, log_cb, shellbags_collector, shellbags_parser),
    "mounteddevices": lambda handler, log_cb: _run_module(handler, log_cb, mounteddevices_collector, mounteddevices_parser),
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
            self.copy_selection()
            return
        super().keyPressEvent(event)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        copy_action = menu.addAction("Copy")
        chosen = menu.exec_(event.globalPos())
        if chosen == copy_action:
            self.copy_selection()

    def copy_selection(self):
        indexes = self.selectedIndexes()
        if not indexes:
            return
        rows = sorted({index.row() for index in indexes})
        cols = sorted({index.column() for index in indexes})
        lines = []
        for row in rows:
            values = []
            for col in cols:
                item = self.item(row, col)
                values.append(item.text() if item else "")
            lines.append("\t".join(values))
        QApplication.clipboard().setText("\n".join(lines))


class StartupDialog(QDialog):
    def __init__(self, recent_files: list[str], parent=None):
        super().__init__(parent)
        self.selected_path = None
        self.setWindowTitle("Start")
        self.setModal(True)
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        button_row = QHBoxLayout()
        self.open_btn = QPushButton("New File")
        self.open_btn.clicked.connect(self._choose_open)
        button_row.addWidget(self.open_btn)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        self.recent_list = QListWidget()
        self.recent_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.recent_list.itemDoubleClicked.connect(lambda _item: self._choose_recent())
        for path in recent_files[:3]:
            item = QListWidgetItem(path)
            item.setToolTip(path)
            self.recent_list.addItem(item)
        if self.recent_list.count():
            self.recent_list.setCurrentRow(0)
        layout.addWidget(self.recent_list)

    def _choose_open(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Image",
            "",
            "Disk Images (*.001 *.dd *.raw *.img);;EWF Images (*.E01 *.e01);;All Files (*)",
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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
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
        self._current_filtered_entries = []
        self._pending_image_path = None

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
        main_split.setSizes([240, 840, 420])
        main_split.setStretchFactor(1, 2)
        main_split.setStretchFactor(2, 1)

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
        self.font_down_btn = QPushButton("\u25BC")
        self.font_down_btn.setObjectName("font_scale_btn")
        self.font_down_btn.setFixedWidth(28)
        self.font_down_btn.setFlat(True)
        self.font_down_btn.clicked.connect(lambda: self._change_font_scale(-10))
        self.status.addPermanentWidget(self.font_down_btn)
        self.font_scale_label = QLabel()
        self.font_scale_label.setObjectName("font_scale_label")
        self.status.addPermanentWidget(self.font_scale_label)
        self.font_up_btn = QPushButton("\u25B2")
        self.font_up_btn.setObjectName("font_scale_btn")
        self.font_up_btn.setFixedWidth(28)
        self.font_up_btn.setFlat(True)
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
        file_header = self.file_table.horizontalHeader()
        file_header.setSectionResizeMode(QHeaderView.Interactive)
        file_header.setMinimumSectionSize(60)
        file_header.setStretchLastSection(False)
        file_header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.file_table.setColumnWidth(0, 420)
        self.file_table.setColumnWidth(1, 110)
        self.file_table.setColumnWidth(2, 90)
        self.file_table.setColumnWidth(3, 90)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.file_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.file_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.file_table.setSortingEnabled(True)
        self.file_table.setShowGrid(False)
        self.file_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self._open_file_context_menu)
        self.file_table.verticalHeader().setVisible(False)
        self.file_table.itemClicked.connect(self._on_file_clicked)
        file_layout.addWidget(self.file_table)

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.meta_view = QTextEdit()
        self.meta_view.setReadOnly(True)
        viewer_tabs = QTabWidget()
        viewer_tabs.setObjectName("viewer_tabs")
        viewer_tabs.setMovable(True)
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
        list_panel = QWidget()
        list_layout = QVBoxLayout(list_panel)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(0)
        self.artifact_list = QListWidget()
        self.artifact_list.setSpacing(2)
        for artifact in ARTIFACT_REGISTRY:
            item = QListWidgetItem(f"  {artifact['label']}")
            item.setData(Qt.UserRole, artifact["id"])
            item.setToolTip(artifact["description"])
            self.artifact_list.addItem(item)
        self.artifact_list.itemClicked.connect(self._on_artifact_clicked)
        list_layout.addWidget(self.artifact_list)

        detail_panel = QWidget()
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(0)
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
        detail_layout.addWidget(info_bar)
        self.result_tabs = QTabWidget()
        self.result_tabs.setObjectName("result_tabs")
        self.result_tabs.setMovable(True)
        summary_tab = QWidget()
        summary_layout = QVBoxLayout(summary_tab)
        summary_layout.setContentsMargins(0, 0, 0, 0)
        summary_layout.setSpacing(0)
        self.result_overview = QTextEdit()
        self.result_overview.setReadOnly(True)
        self.result_overview.setPlaceholderText("Select an artifact and click Run.")
        summary_layout.addWidget(self.result_overview, stretch=1)

        parsed_tab = QWidget()
        parsed_layout = QVBoxLayout(parsed_tab)
        parsed_layout.setContentsMargins(0, 0, 0, 0)
        parsed_layout.setSpacing(0)
        filter_bar = QWidget()
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(8, 4, 8, 4)
        filter_layout.setSpacing(8)
        self.filesystem_filter_label = QLabel("MFT Filter")
        self.filesystem_filter_combo = QComboBox()
        self.filesystem_filter_combo.addItems(["전체", "휴지통만", "문서 확장자만", "최근 24시간만"])
        self.filesystem_filter_combo.currentIndexChanged.connect(self._on_filesystem_filter_changed)
        filter_layout.addWidget(self.filesystem_filter_label)
        filter_layout.addWidget(self.filesystem_filter_combo, stretch=1)
        filter_layout.addStretch(1)
        filter_bar.setVisible(False)
        self.filesystem_filter_bar = filter_bar
        self.result_parsed_table = CopyableTableWidget()
        self.result_parsed_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_parsed_table.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.result_parsed_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.result_parsed_table.setSortingEnabled(True)
        self.result_parsed_table.verticalHeader().setVisible(False)
        self.result_parsed_table.setAlternatingRowColors(True)
        self.result_parsed_table.setWordWrap(False)
        parsed_layout.addWidget(filter_bar)
        parsed_layout.addWidget(self.result_parsed_table, stretch=1)
        self.result_raw = QTextEdit()
        self.result_raw.setReadOnly(True)
        self.result_raw.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        self.result_raw.setContextMenuPolicy(Qt.DefaultContextMenu)
        self.result_tabs.addTab(summary_tab, "Summary")
        self.result_tabs.addTab(self.result_raw, "Raw")
        self.result_tabs.addTab(parsed_tab, "Parsed")
        detail_layout.addWidget(self.result_tabs, stretch=1)

        artifact_split = QSplitter(Qt.Vertical)
        artifact_split.addWidget(list_panel)
        artifact_split.addWidget(detail_panel)
        artifact_split.setChildrenCollapsible(False)
        artifact_split.setSizes([220, 560])
        layout.addWidget(artifact_split, stretch=1)
        if self.artifact_list.count():
            self.artifact_list.setCurrentRow(0)
            self._on_artifact_clicked(self.artifact_list.item(0))
        return panel

    def _open_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Forensic Image", "", "Disk Images (*.001 *.dd *.raw *.img);;EWF Images (*.E01 *.e01);;All Files (*)")
        if not path:
            return
        self._open_image_path(path)

    def _open_image_path(self, path: str):
        self.tree.clear()
        self.file_table.setRowCount(0)
        self.hex_view.clear()
        self.text_view.clear()
        self.meta_view.clear()
        self._item_meta.clear()
        self._artifact_cache.clear()
        self.result_overview.clear()
        self.result_parsed_table.clear()
        self.result_parsed_table.setRowCount(0)
        self.result_parsed_table.setColumnCount(0)
        self.filesystem_filter_combo.setCurrentIndex(0)
        self.filesystem_filter_bar.setVisible(False)
        self.result_raw.clear()
        self.act_export.setEnabled(False)
        self._pending_image_path = path
        worker = LoadImageWorker(path)
        worker.log_msg.connect(self._log)
        worker.done.connect(self._on_image_loaded)
        worker.error.connect(self._on_error)
        self._keep(worker)
        worker.start()

    def _on_image_loaded(self, handler):
        self._handler = handler
        if self._pending_image_path:
            self._remember_recent_image(self._pending_image_path)
            self._pending_image_path = None
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
            worker = ListDirWorker(self._handler, meta["fs"], meta["inode"], meta["path"], item)
            worker.done.connect(self._populate_tree_children)
            worker.error.connect(self._on_error)
            self._keep(worker)
            worker.start()

    def _on_tree_clicked(self, item):
        meta = self._item_meta.get(id(item))
        if not meta:
            return
        worker = ListDirWorker(self._handler, meta["fs"], meta["inode"], meta["path"], item)
        worker.done.connect(self._populate_file_table)
        worker.error.connect(self._on_error)
        self._keep(worker)
        worker.start()

    def _populate_tree_children(self, entries, tree_item):
        tree_item.takeChildren()
        for entry in entries:
            child = QTreeWidgetItem([f"[DIR] {entry.name}" if entry.is_dir else entry.name])
            if entry.is_dir:
                child.addChild(QTreeWidgetItem(["Loading..."]))
            self._item_meta[id(child)] = {"fs": entry._fs, "inode": entry.inode, "path": entry.path, "is_dir": entry.is_dir}
            tree_item.addChild(child)

    def _populate_file_table(self, entries, _item=None):
        self._table_entries = entries
        self._table_fs = self._item_meta.get(id(self.tree.currentItem()), {}).get("fs")
        header = self.file_table.horizontalHeader()
        sort_section = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self.file_table.setSortingEnabled(False)
        self.file_table.setRowCount(0)
        for row, entry in enumerate(entries):
            self.file_table.insertRow(row)
            entry_type = "DIR" if entry.is_dir else self._ext(entry.name)
            cells = [
                SortableTableWidgetItem(
                    entry.name,
                    (0 if entry.is_dir else 1, entry.name.lower()),
                ),
                SortableTableWidgetItem(
                    "" if entry.is_dir else self._fmt_size(entry.size),
                    -1 if entry.is_dir else entry.size,
                ),
                SortableTableWidgetItem(entry_type, entry_type.lower()),
                SortableTableWidgetItem(str(entry.inode), entry.inode),
            ]
            for col, cell in enumerate(cells):
                cell.setForeground(QColor(C_TEXT))
                self.file_table.setItem(row, col, cell)
        self.file_table.setSortingEnabled(True)
        if sort_section >= 0:
            self.file_table.sortItems(sort_section, sort_order)

    def _on_file_clicked(self, item):
        row = item.row()
        if row >= len(self._table_entries):
            return
        entry = self._table_entries[row]
        if entry.is_dir:
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
        text_like_exts = {".txt", ".log", ".csv", ".json", ".xml", ".ini", ".cfg", ".reg", ".py", ".md", ".html", ".htm", ".css", ".js", ".ps1", ".bat"}
        if ext in {".pdf", ".ppt", ".pptx", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar"}:
            self.text_view.setPlainText("Text preview is not useful for this file type.\n\nUse Metadata for quick triage or Hex for low-level inspection.")
            return
        if ext not in text_like_exts and b"\x00" in data[:2048]:
            self.text_view.setPlainText("This file looks binary, so a text preview is intentionally suppressed.\nUse Metadata for quick triage or Hex for raw inspection.")
            return
        self.text_view.setPlainText(data.decode("utf-8", errors="replace")[:8192])

    def _show_metadata(self, entry):
        lines = [
            f"Path: {entry.path}",
            f"Name: {entry.name}",
            f"Type: {'Directory' if entry.is_dir else self._ext(entry.name)}",
            f"Size: {self._fmt_size(entry.size)}",
            f"Inode: {entry.inode}",
            f"Created: {self._fmt_dt(getattr(entry, 'created_time', None))}",
            f"Modified: {self._fmt_dt(getattr(entry, 'modified_time', None))}",
            f"Accessed: {self._fmt_dt(getattr(entry, 'accessed_time', None))}",
            f"Changed: {self._fmt_dt(getattr(entry, 'changed_time', None))}",
        ]
        self.meta_view.setPlainText("\n".join(lines))

    def _open_file_context_menu(self, pos):
        selected_rows = sorted({index.row() for index in self.file_table.selectionModel().selectedRows()})
        if not selected_rows:
            row = self.file_table.indexAt(pos).row()
            if row < 0:
                return
            self.file_table.selectRow(row)
            selected_rows = [row]

        menu = QMenu(self)
        extract_action = menu.addAction("File Extract")
        chosen = menu.exec_(self.file_table.viewport().mapToGlobal(pos))
        if chosen == extract_action:
            self._extract_selected_entries(pos)

    def _extract_selected_entries(self, pos):
        if not self._handler:
            return
        rows = sorted({index.row() for index in self.file_table.selectionModel().selectedRows()})
        entries = [self._table_entries[row] for row in rows if 0 <= row < len(self._table_entries)]
        if not entries:
            return
        default_dir = os.path.join(os.path.expanduser("~"), "Desktop")
        destination_dir = QFileDialog.getExistingDirectory(self, "Select Extraction Folder", default_dir)
        if not destination_dir:
            return
        extracted_count = 0
        for entry in entries:
            try:
                extracted_count += self._handler.extract_entry(entry, destination_dir)
            except Exception as exc:
                self._log(f"[ERROR] extract failed: {entry.path} -> {exc}")
        QToolTip.showText(self.file_table.viewport().mapToGlobal(pos), f"{extracted_count} File(s) was extracted", self.file_table, self.file_table.rect(), 3000)
        self.status.showMessage(f"Extracted {extracted_count} file(s) to {destination_dir}", 5000)

    def _on_artifact_clicked(self, item: QListWidgetItem):
        aid = item.data(Qt.UserRole)
        self._current_aid = aid
        artifact = ARTIFACT_INDEX[aid]
        self.art_title_lbl.setText(artifact["label"])
        self._set_filesystem_filter_visible(aid == "filesystem")
        self.run_btn.setEnabled(self._handler is not None)
        if aid in self._artifact_cache:
            self._display_artifact(aid, self._artifact_cache[aid])
        else:
            self.result_overview.setPlainText(f"{artifact['label']}\n\n{artifact['description']}")
            self.result_parsed_table.clear()
            self.result_parsed_table.setRowCount(0)
            self.result_parsed_table.setColumnCount(0)
            self.result_raw.clear()

    def _run_selected_artifact(self):
        if not self._handler or not self._current_aid:
            return
        self.run_btn.setEnabled(False)
        self.run_btn.setText("...")
        if self._current_aid == "filesystem":
            self.filesystem_filter_combo.setCurrentIndex(0)
        self.result_overview.setPlainText("Collecting and parsing...")
        self.result_parsed_table.clear()
        self.result_parsed_table.setRowCount(0)
        self.result_parsed_table.setColumnCount(0)
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

    def _on_filesystem_filter_changed(self, _index: int):
        if self._current_aid != "filesystem":
            return
        entries = self._artifact_cache.get("filesystem")
        if entries is not None:
            self._display_artifact("filesystem", entries)

    def _on_artifact_error(self, msg: str):
        self._log(msg)
        self.result_overview.setPlainText(msg)
        self.result_parsed_table.clear()
        self.result_parsed_table.setRowCount(0)
        self.result_parsed_table.setColumnCount(0)
        self.result_raw.clear()

    def _display_artifact(self, aid: str, entries: list):
        filtered_entries = self._apply_artifact_filter(aid, entries)
        self._current_filtered_entries = filtered_entries
        if not filtered_entries:
            self.result_overview.setPlainText("No entries were collected.")
            self.result_parsed_table.clear()
            self.result_parsed_table.setRowCount(0)
            self.result_parsed_table.setColumnCount(0)
            self.result_raw.clear()
            return
        artifact = ARTIFACT_INDEX[aid]
        overview_lines = [artifact["label"], "", artifact["description"], f"Entries: {len(filtered_entries)} / {len(entries)}"]
        if aid == "filesystem":
            overview_lines.append(f"Filter: {self.filesystem_filter_combo.currentText()}")
        self.result_overview.setPlainText("\n".join(overview_lines))
        self._populate_parsed_table(aid, filtered_entries)
        sanitized_entries = [self._sanitize_entry_for_display(entry) for entry in filtered_entries]
        raw = json.dumps(sanitized_entries, default=self._json_default, ensure_ascii=False, indent=2)
        self.result_raw.setPlainText(raw)
        self.result_tabs.setCurrentIndex(0)
        self.status.showMessage(f"{aid}: {len(filtered_entries)} entries")

    def _export_results(self):
        if not self._current_aid:
            return
        default_name = f"{self._current_aid}_result.txt"
        path, _ = QFileDialog.getSaveFileName(self, "Save Result", default_name, "Text Files (*.txt)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as stream:
            entries = self._artifact_cache.get(self._current_aid, [])
            stream.write(self._summary_export_text(self._current_aid, entries))
        self._log(f"[INFO] exported result: {path}")

    def _log(self, msg: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_output.append(f"[{timestamp}] {msg}")

    def _on_error(self, msg: str):
        self._log(msg)
        self.status.showMessage(msg)
        self._pending_image_path = None

    def _keep(self, worker):
        self._workers.append(worker)
        worker.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)

    def _change_font_scale(self, delta: int):
        value = max(50, min(200, self._font_scale_percent + delta))
        self._set_font_scale_percent(value)

    def show_startup_dialog(self) -> None:
        dialog = StartupDialog(self._load_recent_images(), self)
        if dialog.exec_() != QDialog.Accepted:
            return
        if dialog.selected_path:
            self._open_image_path(dialog.selected_path)

    def _set_font_scale_percent(self, value: int):
        self._font_scale_percent = value
        self._save_font_scale_percent()
        self._apply_dynamic_fonts()
        self._apply_style()

    def _apply_dynamic_fonts(self):
        self.log_output.setFont(QFont("Consolas", self._scaled_pt(9)))
        self.hex_view.setFont(QFont("Consolas", self._scaled_pt(10)))
        self.text_view.setFont(QFont("Consolas", self._scaled_pt(10)))
        self.meta_view.setFont(QFont("Consolas", self._scaled_pt(10)))
        self.result_overview.setFont(QFont("Consolas", self._scaled_pt(10)))
        self.result_raw.setFont(QFont("Consolas", self._scaled_pt(9)))
        self.result_parsed_table.setFont(QFont("Consolas", self._scaled_pt(9)))
        for index in range(self.artifact_list.count()):
            self.artifact_list.item(index).setFont(QFont("Malgun Gothic", self._scaled_pt(self._base_font_pt)))
        self.font_scale_label.setText(f"{self._font_scale_percent}%")
        self.font_down_btn.setEnabled(self._font_scale_percent > 50)
        self.font_up_btn.setEnabled(self._font_scale_percent < 200)

    def _scaled_pt(self, base_pt: int) -> int:
        return max(int(round(base_pt * self._font_scale_percent / 100)), 1)

    def _load_settings(self) -> dict:
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as stream:
                data = json.load(stream)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_settings(self, data: dict) -> None:
        try:
            with open(SETTINGS_PATH, "w", encoding="utf-8") as stream:
                json.dump(data, stream, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.debug("failed to save ui settings: %s", exc)

    def _load_font_scale_percent(self) -> int:
        try:
            data = self._load_settings()
            value = int(data.get("font_scale_percent", 100))
            return max(50, min(200, value))
        except Exception:
            return 100

    def _save_font_scale_percent(self) -> None:
        data = self._load_settings()
        data["font_scale_percent"] = self._font_scale_percent
        self._save_settings(data)

    def _load_recent_images(self) -> list[str]:
        data = self._load_settings()
        items = data.get("recent_images", [])
        if not isinstance(items, list):
            return []
        return [path for path in items if isinstance(path, str) and os.path.exists(path)][:3]

    def _remember_recent_image(self, path: str) -> None:
        data = self._load_settings()
        items = data.get("recent_images", [])
        if not isinstance(items, list):
            items = []
        normalized = os.path.abspath(path)
        items = [item for item in items if isinstance(item, str) and os.path.exists(item) and os.path.abspath(item) != normalized]
        items.insert(0, normalized)
        data["recent_images"] = items[:3]
        self._save_settings(data)

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
    def _sanitize_entry_for_display(entry: dict) -> dict:
        if not isinstance(entry, dict):
            return entry
        return {key: value for key, value in entry.items() if key != "artifact_weight"}

    def _populate_parsed_table(self, aid: str, entries: list) -> None:
        columns = self._summary_columns(aid)
        self.result_parsed_table.setSortingEnabled(False)
        self.result_parsed_table.clear()
        self.result_parsed_table.setColumnCount(len(columns))
        self.result_parsed_table.setHorizontalHeaderLabels([label for _, label in columns])
        visible_entries = entries[:200]
        self.result_parsed_table.setRowCount(len(visible_entries))
        for row, entry in enumerate(visible_entries):
            mapped = self._summary_row(aid, entry)
            for col, (key, _) in enumerate(columns):
                item = SortableTableWidgetItem(mapped.get(key, ""), self._summary_sort_value(entry, key, mapped.get(key, "")))
                item.setForeground(QColor(C_TEXT))
                self.result_parsed_table.setItem(row, col, item)
        header = self.result_parsed_table.horizontalHeader()
        for index, (key, _) in enumerate(columns):
            if key in {"path", "url", "target_path", "description", "decoded_data"}:
                header.setSectionResizeMode(index, QHeaderView.Stretch)
            else:
                header.setSectionResizeMode(index, QHeaderView.ResizeToContents)
        self.result_parsed_table.setSortingEnabled(True)

    def _summary_columns(self, aid: str) -> list[tuple[str, str]]:
        if aid == "filesystem":
            return [
                ("artifact", "Artifact"),
                ("path", "Path"),
                ("entry_type", "Type"),
                ("size", "Size"),
                ("inode", "Inode"),
                ("created_time", "Created Time"),
                ("modified_time", "Modified Time"),
                ("accessed_time", "Accessed Time"),
                ("changed_time", "Changed Time"),
            ]
        if aid == "lnk":
            return [("user", "User"), ("path", "Path"), ("target_path", "Target Path"), ("last_access", "Last Access")]
        if aid == "eventlog":
            return [("event_id", "Event ID"), ("channel", "Channel"), ("provider", "Provider"), ("timestamp", "Timestamp"), ("description", "Description")]
        if aid == "recentdocs":
            return [("user", "User"), ("document_name", "Document"), ("extension", "Extension"), ("last_written_time", "Last Written Time")]
        if aid == "browser_artifacts":
            return [("browser", "Browser"), ("artifact_type", "Artifact Type"), ("profile", "Profile"), ("url", "URL / Path"), ("title", "Title"), ("timestamp", "Timestamp")]
        if aid == "userassist":
            return [("user", "User"), ("name", "Name"), ("run_count", "Run Count"), ("last_run", "Last Run Time")]
        if aid == "jumplist":
            return [("appname", "App"), ("category", "Category"), ("target_path", "Target Path"), ("access_count", "Access Count"), ("last_access", "Last Access")]
        if aid == "shellbags":
            return [("user", "User"), ("path", "Path"), ("last_written_time", "Last Written Time")]
        if aid == "mounteddevices":
            return [("value_name", "Value Name"), ("mapping_type", "Mapping Type"), ("decoded_data", "Decoded Data")]
        return [("value", "Value")]

    def _summary_row(self, aid: str, entry: dict) -> dict:
        if aid == "filesystem":
            if entry.get("artifact_name") == "$MFT" and entry.get("record_type") == "filesystem_record":
                return {
                    "artifact": "$MFT",
                    "path": entry.get("source_path", ""),
                    "entry_type": "Directory" if entry.get("is_dir") else "File",
                    "size": self._fmt_size(entry.get("size") or 0),
                    "inode": str(entry.get("inode") or ""),
                    "created_time": self._fmt_dt(entry.get("created_time")),
                    "modified_time": self._fmt_dt(entry.get("modified_time")),
                    "accessed_time": self._fmt_dt(entry.get("accessed_time")),
                    "changed_time": self._fmt_dt(entry.get("changed_time")),
                }
            return {
                "artifact": entry.get("artifact_name", ""),
                "path": entry.get("source_path", ""),
                "entry_type": "Raw Artifact",
                "size": self._fmt_size(entry.get("size") or 0),
                "inode": "",
                "created_time": "",
                "modified_time": "",
                "accessed_time": "",
                "changed_time": "",
            }
        if aid == "lnk":
            return {
                "user": entry.get("username", ""),
                "path": entry.get("source_path", ""),
                "target_path": entry.get("target_path") or entry.get("name") or "",
                "last_access": self._fmt_dt(entry.get("access_time")),
            }
        if aid == "eventlog":
            return {
                "event_id": str(entry.get("event_id") or ""),
                "channel": entry.get("channel", ""),
                "provider": entry.get("provider", ""),
                "timestamp": self._fmt_dt(entry.get("timestamp")),
                "description": entry.get("object_name") or entry.get("target_filename") or entry.get("device_description") or entry.get("new_process_name") or "",
            }
        if aid == "recentdocs":
            return {
                "user": entry.get("username", ""),
                "document_name": entry.get("document_name", ""),
                "extension": entry.get("extension", ""),
                "last_written_time": self._fmt_dt(entry.get("last_written_time")),
            }
        if aid == "browser_artifacts":
            return {
                "browser": entry.get("browser", ""),
                "artifact_type": entry.get("artifact_type", ""),
                "profile": entry.get("profile", ""),
                "url": entry.get("url") or entry.get("host") or entry.get("download_path") or "",
                "title": entry.get("title") or entry.get("cookie_name") or "",
                "timestamp": self._fmt_dt(entry.get("timestamp")),
            }
        if aid == "userassist":
            return {
                "user": entry.get("username", ""),
                "name": entry.get("name") or "",
                "run_count": str(entry.get("run_count") or ""),
                "last_run": self._fmt_dt(entry.get("last_run_time")),
            }
        if aid == "jumplist":
            return {
                "appname": entry.get("appname", ""),
                "category": entry.get("category", ""),
                "target_path": entry.get("target_path") or entry.get("name") or "",
                "access_count": str(entry.get("access_count") or ""),
                "last_access": self._fmt_dt(entry.get("access_time")),
            }
        if aid == "shellbags":
            return {
                "user": entry.get("username", ""),
                "path": entry.get("shell_path", ""),
                "last_written_time": self._fmt_dt(entry.get("last_written_time")),
            }
        if aid == "mounteddevices":
            return {
                "value_name": entry.get("value_name", ""),
                "mapping_type": entry.get("mapping_type", ""),
                "decoded_data": entry.get("decoded_data", ""),
            }
        return {"value": str(entry)}

    def _summary_export_text(self, aid: str, entries: list) -> str:
        artifact = ARTIFACT_INDEX[aid]
        entries = self._apply_artifact_filter(aid, entries)
        columns = self._summary_columns(aid)
        lines = [artifact["label"], artifact["description"], f"Entries: {len(entries)}", ""]
        lines.append("\t".join(label for _, label in columns))
        for entry in entries:
            mapped = self._summary_row(aid, entry)
            lines.append("\t".join(mapped.get(key, "") for key, _ in columns))
        return "\n".join(lines)

    def _parsed_export_text(self, aid: str, entries: list) -> str:
        artifact = ARTIFACT_INDEX[aid]
        blocks = [artifact["label"], artifact["description"], f"Entries: {len(entries)}", ""]
        for index, entry in enumerate(entries, start=1):
            sanitized = self._sanitize_entry_for_display(entry)
            blocks.append(f"[{index}]")
            for key, value in sanitized.items():
                if isinstance(value, datetime):
                    value = self._json_default(value)
                blocks.append(f"{key}: {value}")
            blocks.append("")
        return "\n".join(blocks).strip()

    def _apply_artifact_filter(self, aid: str, entries: list) -> list[dict]:
        if aid != "filesystem":
            return entries
        selected = self.filesystem_filter_combo.currentText()
        if selected == "전체":
            return entries

        filtered = []
        recent_cutoff = datetime.now(timezone.utc).timestamp() - (24 * 60 * 60)
        doc_exts = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".hwp", ".hwpx", ".txt", ".csv"}

        for entry in entries:
            if entry.get("artifact_name") != "$MFT" or entry.get("record_type") != "filesystem_record":
                continue
            path = (entry.get("source_path") or "").lower()
            if selected == "휴지통만":
                if "/$recycle.bin/" in path:
                    filtered.append(entry)
                continue
            if selected == "문서 확장자만":
                if os.path.splitext(path)[1] in doc_exts:
                    filtered.append(entry)
                continue
            if selected == "최근 24시간만":
                timestamps = [
                    entry.get("created_time"),
                    entry.get("modified_time"),
                    entry.get("accessed_time"),
                    entry.get("changed_time"),
                ]
                if any(ts and ts.timestamp() >= recent_cutoff for ts in timestamps):
                    filtered.append(entry)
                continue
        return filtered

    def _set_filesystem_filter_visible(self, visible: bool) -> None:
        self.filesystem_filter_bar.setVisible(visible)

    def _summary_sort_value(self, entry: dict, key: str, display_value: str):
        if key in {"created_time", "modified_time", "accessed_time", "changed_time"}:
            ts = entry.get(key)
            return ts.timestamp() if ts else float("-inf")
        if key == "size":
            return entry.get("size") or 0
        if key == "inode":
            return entry.get("inode") or 0
        return (display_value or "").lower()

    @staticmethod
    def _file_icon(name):
        ext = os.path.splitext(name)[1].lower()
        icons = {".exe": "[EXE]", ".dll": "[DLL]", ".sys": "[SYS]", ".txt": "[TXT]", ".log": "[LOG]", ".csv": "[CSV]", ".dat": "[DAT]", ".db": "[DB]", ".sqlite": "[DB]", ".lnk": "[LNK]", ".jpg": "[IMG]", ".png": "[IMG]", ".zip": "[ZIP]", ".rar": "[ZIP]"}
        return icons.get(ext, "[FILE]")

    def _apply_style(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{ background-color: {C_BG}; color: {C_TEXT}; font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; font-size: {self._scaled_pt(self._base_font_pt)}pt; }}
            QToolBar {{ background-color: {C_HEADER}; border-bottom: 1px solid {C_BORDER}; spacing: 4px; padding: 4px 10px; }}
            QToolBar QToolButton {{ background: transparent; color: {C_TEXT}; padding: 5px 14px; border-radius: 5px; font-size: {self._scaled_pt(self._base_font_pt)}pt; }}
            QToolBar QToolButton:hover {{ background: {C_SELECT}; color: {C_BLUE}; }}
            QLabel#panel_header {{ background: {C_HEADER}; color: {C_BLUE}; font-weight: bold; font-size: {max(self._scaled_pt(self._base_font_pt - 1), 8)}pt; padding-left: 8px; border-bottom: 1px solid {C_BORDER}; }}
            QLabel#log_header {{ background: {C_HEADER}; color: {C_SUBTEXT}; font-size: {max(self._scaled_pt(self._base_font_pt - 2), 8)}pt; padding-left: 8px; }}
            QLabel#art_title {{ font-weight: bold; font-size: {self._scaled_pt(self._base_font_pt)}pt; color: {C_TEXT}; }}
            QLabel#font_scale_label {{ color: {C_TEXT}; padding: 0 4px; min-width: 44px; }}
            QTreeWidget {{ background: {C_PANEL}; border: none; border-right: 1px solid {C_BORDER}; }}
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {{ background: {C_SELECT}; color: {C_BLUE}; }}
            QTableWidget {{ background: {C_PANEL}; border: none; gridline-color: {C_BORDER}; }}
            QHeaderView::section {{ background: {C_HEADER}; color: {C_SUBTEXT}; border: none; border-bottom: 1px solid {C_BORDER}; border-right: 1px solid {C_BORDER}; padding: 4px 8px; font-size: {max(self._scaled_pt(self._base_font_pt - 1), 8)}pt; }}
            QListWidget {{ background: {C_PANEL}; border: none; border-bottom: 1px solid {C_BORDER}; outline: none; }}
            QListWidget::item {{ padding: 10px 6px; border-bottom: 1px solid {C_BORDER}; color: {C_TEXT}; }}
            QPushButton#run_btn {{ background: {C_BLUE}; color: white; border: none; border-radius: 4px; padding: 5px 10px; font-weight: bold; font-size: {max(self._scaled_pt(self._base_font_pt - 1), 8)}pt; }}
            QPushButton#run_btn:hover {{ background: #1d4ed8; }}
            QPushButton#run_btn:disabled {{ background: {C_SUBTEXT}; }}
            QPushButton#font_scale_btn {{ background: transparent; color: {C_TEXT}; border: none; padding: 0 2px; min-width: 20px; }}
            QPushButton#font_scale_btn:hover {{ color: {C_BLUE}; }}
            QPushButton#font_scale_btn:pressed {{ color: #1d4ed8; }}
            QPushButton#font_scale_btn:disabled {{ color: {C_SUBTEXT}; }}
            QTabWidget#viewer_tabs::pane, QTabWidget#result_tabs::pane {{ border: 1px solid {C_BORDER}; background: {C_PANEL}; }}
            QTabBar::tab {{ background: {C_HEADER}; color: {C_SUBTEXT}; padding: 5px 16px; border-top-left-radius: 4px; border-top-right-radius: 4px; margin-right: 2px; }}
            QTabBar::tab:selected {{ background: {C_PANEL}; color: {C_BLUE}; border-bottom: 2px solid {C_BLUE}; font-weight: normal; }}
            QTextEdit {{ background: {C_PANEL}; color: {C_TEXT}; border: none; selection-background-color: {C_SELECT}; selection-color: {C_BLUE}; }}
            QFrame#divider {{ color: {C_BORDER}; }}
            QStatusBar {{ background: {C_HEADER}; color: {C_SUBTEXT}; font-size: {max(self._scaled_pt(self._base_font_pt - 1), 8)}pt; }}
            QSplitter::handle {{ background: {C_BORDER}; width: 1px; height: 1px; }}
        """)
