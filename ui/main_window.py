import html
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QColor, QFont, QIcon, QKeySequence
from PyQt5.QtWidgets import (
    QShortcut,
    QAbstractItemView,
    QAction,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTabBar,
    QTabWidget,
    QTextEdit,
    QToolTip,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .constants      import C_AMBER, C_BLUE, C_TEXT, ARTIFACT_INDEX, ARTIFACT_REGISTRY
from .workers        import ArtifactWorker, ListDirWorker, LoadImageWorker
from .widgets        import CopyableTableWidget, SortableTableWidgetItem, StartupDialog, TimelineExplorerWidget, ProgressDialog
from .mixins         import SettingsMixin, StyleMixin
from . import artifact_columns as ac

logger = logging.getLogger(__name__)

# Parsed 탭에서 한 번에 보여 줄 최대 행 수
_MAX_TABLE_ROWS = 200
_MAX_RAW_JSON_ROWS = 300


class MainWindow(SettingsMixin, StyleMixin, QMainWindow):

    def __init__(self):
        super().__init__()
        self._base_font_pt       = 10
        self._font_scale_percent = self._load_font_scale_percent()

        self.setWindowTitle("Insider Exfiltration Tool")
        icon_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "Icon.png"))
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.setGeometry(100, 100, 1500, 900)
        self.setMinimumSize(1100, 650)

        # 런타임 상태
        self._handler:                 object       = None
        self._workers:                 list         = []
        self._item_meta:               dict         = {}
        self._table_entries:           list         = []
        self._table_fs:                object       = None
        self._artifact_cache:          dict         = {}
        self._current_aid:             str | None   = None
        self._current_filtered_entries:list         = []
        self._pending_image_path:      str | None   = None
        self._progress_dialog:         ProgressDialog | None = None

        self._init_ui()
        self._apply_dynamic_fonts()
        self._apply_style()

    # ═══════════════════════════════════════════════════════
    # UI 구성
    # ═══════════════════════════════════════════════════════

    def _init_ui(self):
        # ── 툴바 ──────────────────────────────────────────
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)

        act_open = QAction("Open Image", self)
        act_open.triggered.connect(self._open_image)
        self.act_timeline = QAction("Timeline", self)
        self.act_timeline.setEnabled(False)
        self.act_timeline.triggered.connect(self._open_timeline)
        self.act_export = QAction("Export Result", self)
        self.act_export.setEnabled(False)
        self.act_export.triggered.connect(self._export_results)
        toolbar.addAction(act_open)
        toolbar.addAction(self.act_timeline)
        toolbar.addSeparator()
        toolbar.addAction(self.act_export)

        # ── 3-패널 분할 ───────────────────────────────────
        main_split = QSplitter(Qt.Horizontal)
        main_split.addWidget(self._make_evidence_tree())
        main_split.addWidget(self._make_file_browser())
        main_split.addWidget(self._make_artifact_panel())
        main_split.setSizes([240, 840, 420])
        main_split.setStretchFactor(1, 2)
        main_split.setStretchFactor(2, 1)

        workspace_page = QWidget()
        workspace_layout = QVBoxLayout(workspace_page)
        workspace_layout.setContentsMargins(0, 0, 0, 0)
        workspace_layout.setSpacing(0)
        workspace_layout.addWidget(main_split)

        self.timeline_page = QWidget()
        timeline_layout = QVBoxLayout(self.timeline_page)
        timeline_layout.setContentsMargins(0, 0, 0, 0)
        timeline_layout.setSpacing(0)
        self.timeline_page_widget = TimelineExplorerWidget([], self)
        self.timeline_page_widget.detail_navigation_requested.connect(self._open_timeline_detail_target)
        timeline_layout.addWidget(self.timeline_page_widget)
        self._timeline_tab_index = None
        self._timeline_entries_ref = None

        self.main_pages = QTabWidget()
        self.main_pages.setObjectName("main_pages")
        self.main_pages.setTabsClosable(True)
        self.main_pages.tabCloseRequested.connect(self._close_main_tab)
        self.main_pages.addTab(workspace_page, "File System")
        self.main_pages.tabBar().setTabButton(0, QTabBar.RightSide, None)
        self.main_pages.setCurrentIndex(0)

        # ── 로그 패널 ─────────────────────────────────────
        log_panel  = QWidget()
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

        # ── 루트 레이아웃 ─────────────────────────────────
        root = QVBoxLayout()
        root.setContentsMargins(4, 4, 4, 4)
        root.setSpacing(4)
        root.addWidget(self.main_pages, stretch=1)
        root.addWidget(log_panel)
        container = QWidget()
        container.setLayout(root)
        self.setCentralWidget(container)

        # ── 상태바 (폰트 스케일 버튼 포함) ───────────────
        self.status = QStatusBar()
        self.setStatusBar(self.status)

        self.font_down_btn = QPushButton("\u25BC")
        self.font_down_btn.setObjectName("font_scale_btn")
        self.font_down_btn.setFixedWidth(28)
        self.font_down_btn.setFlat(True)
        self.font_down_btn.clicked.connect(lambda: self._change_font_scale(-10))

        self.font_scale_label = QLabel()
        self.font_scale_label.setObjectName("font_scale_label")

        self.font_up_btn = QPushButton("\u25B2")
        self.font_up_btn.setObjectName("font_scale_btn")
        self.font_up_btn.setFixedWidth(28)
        self.font_up_btn.setFlat(True)
        self.font_up_btn.clicked.connect(lambda: self._change_font_scale(10))

        self.status.addPermanentWidget(self.font_down_btn)
        self.status.addPermanentWidget(self.font_scale_label)
        self.status.addPermanentWidget(self.font_up_btn)
        self.status.showMessage("Open a forensic image to start.")

        QShortcut(QKeySequence("Ctrl+Q"), self).activated.connect(self.close)

    # ── 패널 팩토리 ───────────────────────────────────────

    def _make_evidence_tree(self) -> QWidget:
        panel  = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        label = QLabel("  All Evidence")
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
        file_panel  = QWidget()
        file_layout = QVBoxLayout(file_panel)
        file_layout.setContentsMargins(0, 0, 0, 0)
        file_layout.setSpacing(0)

        label = QLabel("  Evidence")
        label.setFixedHeight(28)
        label.setObjectName("panel_header")
        file_layout.addWidget(label)

        self.file_path_bar = QLabel("  Path: /")
        self.file_path_bar.setFixedHeight(28)
        self.file_path_bar.setObjectName("path_bar")
        file_layout.addWidget(self.file_path_bar)

        self.file_table = CopyableTableWidget()
        self.file_table.setColumnCount(4)
        self.file_table.setHorizontalHeaderLabels(["Name", "Size", "Type", "Inode"])
        fh = self.file_table.horizontalHeader()
        fh.setSectionResizeMode(QHeaderView.Interactive)
        fh.setMinimumSectionSize(60)
        fh.setStretchLastSection(False)
        fh.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.file_table.setColumnWidth(0, 420)
        self.file_table.setColumnWidth(1, 110)
        self.file_table.setColumnWidth(2,  90)
        self.file_table.setColumnWidth(3,  90)
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
        return file_panel

        # 하단 뷰어 탭
        self.hex_view  = QTextEdit(); self.hex_view.setReadOnly(True)
        self.text_view = QTextEdit(); self.text_view.setReadOnly(True)
        self.meta_view = QTextEdit(); self.meta_view.setReadOnly(True)

        viewer_tabs = QTabWidget()
        viewer_tabs.setObjectName("viewer_tabs")
        viewer_tabs.setMovable(True)
        viewer_tabs.addTab(self.text_view, "Text")
        viewer_tabs.addTab(self.hex_view,  "Hex")
        viewer_tabs.addTab(self.meta_view, "Metadata")

        split = QSplitter(Qt.Vertical)
        split.addWidget(file_panel)
        split.addWidget(viewer_tabs)
        split.setSizes([400, 260])
        return split

    def _make_artifact_panel(self) -> QWidget:
        panel  = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        label = QLabel("  Artifacts")
        label.setFixedHeight(28)
        label.setObjectName("panel_header")
        layout.addWidget(label)

        # 아티팩트 목록
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.meta_view = QTextEdit()
        self.meta_view.setReadOnly(True)
        self.preview_view = QTextEdit()
        self.preview_view.setReadOnly(True)
        self.preview_view.setMaximumHeight(180)

        inspector_tab = QWidget()
        inspector_layout = QVBoxLayout(inspector_tab)
        inspector_layout.setContentsMargins(0, 0, 0, 0)
        inspector_layout.setSpacing(0)

        self.file_inspector_title = QLabel("No file selected")
        self.file_inspector_title.setObjectName("art_title")
        self.file_inspector_title.setContentsMargins(10, 8, 10, 8)
        inspector_layout.addWidget(self.file_inspector_title)

        preview_label = QLabel("  Preview")
        preview_label.setFixedHeight(28)
        preview_label.setObjectName("path_bar")
        inspector_layout.addWidget(preview_label)
        inspector_layout.addWidget(self.preview_view)

        details_label = QLabel("  Details")
        details_label.setFixedHeight(28)
        details_label.setObjectName("path_bar")
        inspector_layout.addWidget(details_label)
        inspector_split = QSplitter(Qt.Vertical)
        inspector_split.setChildrenCollapsible(False)
        inspector_split.addWidget(self.meta_view)

        self.inspector_viewer_tabs = QTabWidget()
        self.inspector_viewer_tabs.setObjectName("viewer_tabs")
        self.inspector_viewer_tabs.setMovable(True)
        self.inspector_viewer_tabs.addTab(self.text_view, "Text")
        self.inspector_viewer_tabs.addTab(self.hex_view, "Hex")
        inspector_split.addWidget(self.inspector_viewer_tabs)
        inspector_split.setSizes([260, 360])
        inspector_layout.addWidget(inspector_split, stretch=1)

        list_panel  = QWidget()
        list_layout = QVBoxLayout(list_panel)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(0)

        self.artifact_list = QListWidget()
        self.artifact_list.setSpacing(2)
        for artifact in ARTIFACT_REGISTRY:
            if artifact["id"] == "timeline":
                continue
            item = QListWidgetItem(f"  {artifact['label']}")
            item.setData(Qt.UserRole, artifact["id"])
            item.setToolTip(artifact["description"])
            self.artifact_list.addItem(item)
        self.artifact_list.itemClicked.connect(self._on_artifact_clicked)
        list_layout.addWidget(self.artifact_list)

        # 결과 패널
        detail_panel  = QWidget()
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(0)

        info_bar    = QWidget()
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

        # Summary 탭
        summary_tab    = QWidget()
        summary_layout = QVBoxLayout(summary_tab)
        summary_layout.setContentsMargins(0, 0, 0, 0)
        self.result_overview = QTextEdit()
        self.result_overview.setReadOnly(True)
        self.result_overview.setPlaceholderText("Select an artifact and run it.")
        summary_layout.addWidget(self.result_overview)

        # Parsed 탭
        parsed_tab    = QWidget()
        parsed_layout = QVBoxLayout(parsed_tab)
        parsed_layout.setContentsMargins(0, 0, 0, 0)
        parsed_layout.setSpacing(0)

        filter_bar    = QWidget()
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(8, 4, 8, 4)
        filter_layout.setSpacing(8)
        self.filesystem_filter_label = QLabel("MFT Filter")
        self.filesystem_filter_combo = QComboBox()
        self.filesystem_filter_combo.addItems(["All", "Recycle Bin Only", "Document Extensions Only", "Recent 24 Hours"])
        self.filesystem_filter_combo.currentIndexChanged.connect(self._on_filesystem_filter_changed)
        self.filesystem_filter_combo.clear()
        self.filesystem_filter_combo.addItems([
            "All",
            "Recycle Bin Only",
            "Document Extensions Only",
            "Recent 24 Hours",
        ])
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

        # Raw 탭
        self.result_raw = QTextEdit()
        self.result_raw.setReadOnly(True)
        self.result_raw.setTextInteractionFlags(
            Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard
        )
        self.result_raw.setContextMenuPolicy(Qt.DefaultContextMenu)

        self.result_tabs.addTab(summary_tab,    "Summary")
        self.result_tabs.addTab(self.result_raw,"Raw")
        self.result_tabs.addTab(parsed_tab,     "Parsed")
        detail_layout.addWidget(self.result_tabs, stretch=1)

        artifact_split = QSplitter(Qt.Vertical)
        artifact_split.addWidget(list_panel)
        artifact_split.addWidget(detail_panel)
        artifact_split.setChildrenCollapsible(False)
        artifact_split.setSizes([220, 560])
        self.side_panel_tabs = QTabWidget()
        self.side_panel_tabs.setObjectName("result_tabs")
        self.side_panel_tabs.addTab(inspector_tab, "Inspector")
        self.side_panel_tabs.addTab(artifact_split, "Artifacts")
        layout.addWidget(self.side_panel_tabs, stretch=1)

        # 초기 선택
        if self.artifact_list.count():
            self.artifact_list.setCurrentRow(0)
            self._on_artifact_clicked(self.artifact_list.item(0))

        return panel

    # ═══════════════════════════════════════════════════════
    # 이미지 열기
    # ═══════════════════════════════════════════════════════

    def show_startup_dialog(self) -> None:
        dialog = StartupDialog(self._load_recent_images(), self)
        if dialog.exec_() != QDialog.Accepted:
            return
        if dialog.selected_path:
            self._open_image_path(dialog.selected_path)

    def _open_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Forensic Image", "",
            "Disk Images (*.001 *.dd *.raw *.img);;"
            "EWF Images (*.E01 *.e01);;"
            "All Files (*)"
        )
        if path:
            self._open_image_path(path)

    def _open_image_path(self, path: str):
        self._reset_ui()
        self._pending_image_path = path
        worker = LoadImageWorker(path)
        worker.log_msg.connect(self._log)
        worker.done.connect(self._on_image_loaded)
        worker.error.connect(self._on_error)
        self._keep(worker)
        worker.start()

    def _reset_ui(self):
        self.main_pages.setCurrentIndex(0)
        self._timeline_entries_ref = None
        if self._timeline_tab_index is not None:
            self.main_pages.removeTab(self._timeline_tab_index)
            self._timeline_tab_index = None
        self.tree.clear()
        self.file_table.setRowCount(0)
        self._set_file_path_bar("/")
        self.hex_view.clear()
        self.text_view.clear()
        self.meta_view.clear()
        if hasattr(self, "preview_view"):
            self.preview_view.clear()
        if hasattr(self, "file_inspector_title"):
            self.file_inspector_title.setText("No file selected")
        self._item_meta.clear()
        self._artifact_cache.clear()
        self.timeline_page_widget.set_events([])
        self.result_overview.clear()
        self.result_parsed_table.clear()
        self.result_parsed_table.setRowCount(0)
        self.result_parsed_table.setColumnCount(0)
        self.filesystem_filter_combo.setCurrentIndex(0)
        self.filesystem_filter_bar.setVisible(False)
        self._configure_filter_bar("")
        self.result_raw.clear()
        self.act_export.setEnabled(False)
        self.act_timeline.setEnabled(False)

    # ═══════════════════════════════════════════════════════
    # 이벤트 핸들러 — 이미지·트리·파일
    # ═══════════════════════════════════════════════════════

    def _on_image_loaded(self, handler):
        self._handler = handler
        if self._pending_image_path:
            self._remember_recent_image(self._pending_image_path)
            self._pending_image_path = None
        self.status.showMessage(f"Image loaded: {os.path.basename(handler.image_path)}")
        self._log(f"[INFO] image loaded with {len(handler.volumes)} volume(s)")
        self.act_timeline.setEnabled(True)

        root_item = QTreeWidgetItem([f"[IMG] {os.path.basename(handler.image_path)}"])
        root_item.setForeground(0, QColor(C_AMBER))
        self.tree.addTopLevelItem(root_item)
        for vol in handler.volumes:
            vol_item = QTreeWidgetItem([f"[VOL] {vol['desc']}"])
            vol_item.setForeground(0, QColor(C_BLUE))
            self._item_meta[id(vol_item)] = {
                "fs": vol["fs"], "inode": None, "path": "/", "is_dir": True
            }
            vol_item.addChild(QTreeWidgetItem(["Loading..."]))
            root_item.addChild(vol_item)
        root_item.setExpanded(True)
        self.run_btn.setEnabled(self._current_aid is not None)

    def _on_tree_expanded(self, item):
        meta = self._item_meta.get(id(item))
        if not meta:
            return
        if item.childCount() == 1 and item.child(0).text(0) == "Loading...":
            worker = ListDirWorker(
                self._handler, meta["fs"], meta["inode"], meta["path"], item
            )
            worker.done.connect(self._populate_tree_children)
            worker.error.connect(self._on_error)
            self._keep(worker)
            worker.start()

    def _on_tree_clicked(self, item):
        self.main_pages.setCurrentIndex(0)
        meta = self._item_meta.get(id(item))
        if not meta:
            return
        self._set_file_path_bar(meta.get("path", "/"))
        worker = ListDirWorker(
            self._handler, meta["fs"], meta["inode"], meta["path"], item
        )
        worker.done.connect(self._populate_file_table)
        worker.error.connect(self._on_error)
        self._keep(worker)
        worker.start()

    def _populate_tree_children(self, entries, tree_item):
        tree_item.takeChildren()
        for entry in entries:
            label = f"[DIR] {entry.name}" if entry.is_dir else entry.name
            child = QTreeWidgetItem([label])
            if entry.is_dir:
                child.addChild(QTreeWidgetItem(["Loading..."]))
            self._item_meta[id(child)] = {
                "fs": entry._fs, "inode": entry.inode,
                "path": entry.path, "is_dir": entry.is_dir,
            }
            tree_item.addChild(child)

    def _populate_file_table(self, entries, _item=None):
        self._table_entries = entries
        self._table_fs = (
            self._item_meta
            .get(id(self.tree.currentItem()), {})
            .get("fs")
        )
        current_path = (
            self._item_meta
            .get(id(self.tree.currentItem()), {})
            .get("path", "/")
        )
        self._set_file_path_bar(current_path)
        header       = self.file_table.horizontalHeader()
        sort_section = header.sortIndicatorSection()
        sort_order   = header.sortIndicatorOrder()

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
                cell.setData(Qt.UserRole, entry)
                self.file_table.setItem(row, col, cell)
        self.file_table.setSortingEnabled(True)
        if sort_section >= 0:
            self.file_table.sortItems(sort_section, sort_order)

    def _set_file_path_bar(self, path: str) -> None:
        path = path or "/"
        display_path = path if len(path) <= 120 else f"...{path[-117:]}"
        self.file_path_bar.setText(f"  Path: {display_path}")

    def _on_file_clicked(self, item):
        self.main_pages.setCurrentIndex(0)
        self.side_panel_tabs.setCurrentIndex(0)
        entry = self._entry_for_row(item.row())
        if entry is None:
            return
        if entry.is_dir:
            self._set_file_path_bar(entry.path)
            self._table_entries = self._handler.list_directory(
                entry._fs, entry.inode, entry.path
            )
            self._table_fs = entry._fs
            self._populate_file_table(self._table_entries)
            self._show_metadata(entry)
            self.hex_view.clear()
            self.text_view.clear()
            self.preview_view.setPlainText("Directory selected. Choose a file to inspect preview content.")
            self.status.showMessage(f"{entry.path} (directory)")
            return
        self._show_file_entry(entry)

    # ─── 파일 뷰어 ────────────────────────────────────────

    def _show_hex(self, data: bytes, base_offset: int = 0, highlight_offset: Optional[int] = None):
        rows = []
        for i in range(0, min(len(data), 4096), 16):
            chunk = data[i:i + 16]
            hex_cells = []
            text_cells = []
            for j, byte in enumerate(chunk):
                absolute_offset = base_offset + i + j
                byte_text = f"{byte:02X}"
                char_text = chr(byte) if 32 <= byte < 127 else "."
                if highlight_offset is not None and absolute_offset == highlight_offset:
                    hex_cells.append(
                        f'<span style="background:#dbeafe; color:#1d4ed8; font-weight:700;">{byte_text}</span>'
                    )
                    text_cells.append(
                        f'<span style="background:#dbeafe; color:#1d4ed8; font-weight:700;">{html.escape(char_text)}</span>'
                    )
                else:
                    hex_cells.append(byte_text)
                    text_cells.append(html.escape(char_text))
            hex_part = " ".join(hex_cells).ljust(48)
            text_part = "".join(text_cells)
            rows.append(
                f"{base_offset + i:08X}  {hex_part}  {text_part}"
            )
        html_text = (
            '<pre style="font-family:Consolas, \'Courier New\', monospace; '
            'font-size:10pt; line-height:1.45; color:#0f172a; margin:0;">'
            + "\n".join(rows)
            + "</pre>"
        )
        self.hex_view.setHtml(html_text)

    def _show_text(self, data: bytes, name: str):
        ext = os.path.splitext(name)[1].lower()
        binary_exts = {
            ".pdf", ".ppt", ".pptx", ".doc", ".docx",
            ".xls", ".xlsx", ".zip", ".rar",
        }
        text_exts = {
            ".txt", ".log", ".csv", ".json", ".xml",
            ".ini", ".cfg", ".reg", ".py", ".md",
            ".html", ".htm", ".css", ".js", ".ps1", ".bat",
        }
        if ext in binary_exts:
            message = (
                "Text preview is not useful for this file type.\n\n"
                "Use Metadata for quick triage or Hex for low-level inspection."
            )
            self.text_view.setPlainText(message)
            self.preview_view.setPlainText("Preview unavailable for this binary file type.")
            return
        if ext not in text_exts and b"\x00" in data[:2048]:
            message = (
                "This file looks binary, so a text preview is intentionally suppressed.\n"
                "Use Metadata for quick triage or Hex for raw inspection."
            )
            self.text_view.setPlainText(message)
            self.preview_view.setPlainText("Preview suppressed because the file appears to be binary.")
            return
        text = data.decode("utf-8", errors="replace")[:8192]
        self.text_view.setPlainText(text)
        preview_text = text[:1600].strip()
        self.preview_view.setPlainText(preview_text or "No previewable text was found.")

    def _show_metadata(self, entry):
        self.file_inspector_title.setText(entry.name or "Unnamed entry")
        lines = [
            f"Path: {entry.path}",
            f"Name: {entry.name}",
            f"Type: {'Directory' if entry.is_dir else self._ext(entry.name)}",
            f"Size: {self._fmt_size(entry.size)}",
            f"Inode: {entry.inode}",
            f"Created:  {self._fmt_dt(getattr(entry, 'created_time',  None))}",
            f"Modified: {self._fmt_dt(getattr(entry, 'modified_time', None))}",
            f"Accessed: {self._fmt_dt(getattr(entry, 'accessed_time', None))}",
            f"Changed:  {self._fmt_dt(getattr(entry, 'changed_time',  None))}",
        ]
        self.meta_view.setPlainText("\n".join(lines))

    def _entry_for_row(self, row: int):
        item = self.file_table.item(row, 0)
        return item.data(Qt.UserRole) if item is not None else None

    def _normalize_fs_path(self, path: str) -> str:
        normalized = (path or "/").replace("\\", "/")
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        while "//" in normalized:
            normalized = normalized.replace("//", "/")
        if len(normalized) > 1:
            normalized = normalized.rstrip("/")
        return normalized or "/"

    def _split_fs_path(self, path: str) -> tuple[str, str]:
        normalized = self._normalize_fs_path(path)
        if normalized == "/":
            return "/", ""
        parent, _, name = normalized.rpartition("/")
        return (parent or "/"), name

    def _find_entry_by_path(self, path: str):
        target_path = self._normalize_fs_path(path)
        parent_path, name = self._split_fs_path(target_path)
        for volume in getattr(self._handler, "volumes", []):
            fs = volume.get("fs")
            if fs is None:
                continue
            try:
                entries = self._handler.list_directory(fs, path=parent_path)
            except Exception:
                continue
            for entry in entries:
                if self._normalize_fs_path(entry.path) == target_path:
                    return fs, entries, entry
            lower_name = name.lower()
            for entry in entries:
                if entry.name.lower() == lower_name:
                    return fs, entries, entry
        return None

    def _select_file_row_by_path(self, path: str) -> bool:
        target_path = self._normalize_fs_path(path)
        for row in range(self.file_table.rowCount()):
            entry = self._entry_for_row(row)
            if entry is None:
                continue
            if self._normalize_fs_path(entry.path) == target_path:
                self.file_table.selectRow(row)
                self.file_table.scrollToItem(self.file_table.item(row, 0))
                return True
        return False

    def _read_file_window(self, fs, inode: int, offset: int, window_size: int = 4096) -> tuple[bytes, int]:
        try:
            file_obj = fs.open_meta(inode=inode)
            meta = getattr(file_obj.info, "meta", None)
            if meta is None:
                return b"", 0
            size = int(getattr(meta, "size", 0) or 0)
            if size <= 0:
                return b"", 0
            clamped_offset = max(0, min(int(offset), max(0, size - 1)))
            start = max(0, min(clamped_offset - (window_size // 2), max(0, size - window_size)))
            length = min(window_size, size - start)
            return file_obj.read_random(start, length), start
        except Exception as exc:
            self._log(f"[WARN] failed to read file window: inode={inode} offset={offset} -> {exc}")
            return b"", 0

    def _show_file_entry(self, entry, highlight_offset: Optional[int] = None) -> None:
        fs = getattr(entry, "_fs", None) or self._table_fs
        if fs is None:
            return
        text_data = self._handler.read_file(fs, entry.inode, max_bytes=64 * 1024)
        if highlight_offset is not None:
            hex_data, base_offset = self._read_file_window(fs, entry.inode, highlight_offset)
        else:
            hex_data, base_offset = text_data, 0
        self._show_metadata(entry)
        self._show_hex(hex_data, base_offset=base_offset, highlight_offset=highlight_offset)
        self._show_text(text_data, entry.name)
        if hasattr(self, "inspector_viewer_tabs"):
            self.inspector_viewer_tabs.setCurrentIndex(1 if highlight_offset is not None else 0)
        if highlight_offset is None:
            self.status.showMessage(f"{entry.path} ({self._fmt_size(entry.size)})")
        else:
            self.status.showMessage(
                f"{entry.path} ({self._fmt_size(entry.size)})  |  Offset: 0x{highlight_offset:X}"
            )

    def _open_timeline_detail_target(self, path: str, offset: int) -> None:
        if not self._handler:
            return
        target_path = self._normalize_fs_path(path)
        found = self._find_entry_by_path(target_path)
        if found is None:
            self.status.showMessage(f"Could not locate {target_path} in the file system view.")
            return
        fs, entries, entry = found
        self.main_pages.setCurrentIndex(0)
        self.side_panel_tabs.setCurrentIndex(0)
        self._table_entries = entries
        self._table_fs = fs
        self._populate_file_table(entries)
        self._set_file_path_bar(self._split_fs_path(target_path)[0])
        self._select_file_row_by_path(target_path)
        self._show_file_entry(entry, highlight_offset=max(0, int(offset or 0)))

    # ─── 파일 컨텍스트 메뉴 ──────────────────────────────

    def _open_file_context_menu(self, pos):
        selected_rows = sorted(
            {idx.row() for idx in self.file_table.selectionModel().selectedRows()}
        )
        if not selected_rows:
            row = self.file_table.indexAt(pos).row()
            if row < 0:
                return
            self.file_table.selectRow(row)
            selected_rows = [row]

        from PyQt5.QtWidgets import QMenu
        menu = QMenu(self)
        extract_action = menu.addAction("File Extract")
        chosen = menu.exec_(self.file_table.viewport().mapToGlobal(pos))
        if chosen == extract_action:
            self._extract_selected_entries(pos)

    def _extract_selected_entries(self, pos):
        if not self._handler:
            return
        rows    = sorted(
            {idx.row() for idx in self.file_table.selectionModel().selectedRows()}
        )
        entries = [
            self._table_entries[r]
            for r in rows
            if 0 <= r < len(self._table_entries)
        ]
        if not entries:
            return
        default_dir     = os.path.join(os.path.expanduser("~"), "Desktop")
        destination_dir = QFileDialog.getExistingDirectory(
            self, "Select Extraction Folder", default_dir
        )
        if not destination_dir:
            return
        extracted_count = 0
        for entry in entries:
            try:
                extracted_count += self._handler.extract_entry(entry, destination_dir)
            except Exception as exc:
                self._log(f"[ERROR] extract failed: {entry.path} -> {exc}")
        QToolTip.showText(
            self.file_table.viewport().mapToGlobal(pos),
            f"{extracted_count} File(s) was extracted",
            self.file_table,
            self.file_table.rect(),
            3000,
        )
        self.status.showMessage(
            f"Extracted {extracted_count} file(s) to {destination_dir}", 5000
        )

    # ═══════════════════════════════════════════════════════
    # 이벤트 핸들러 — 아티팩트
    # ═══════════════════════════════════════════════════════

    def _on_artifact_clicked(self, item: QListWidgetItem):
        if hasattr(self, "main_pages"):
            self.main_pages.setCurrentIndex(0)
        if hasattr(self, "side_panel_tabs"):
            self.side_panel_tabs.setCurrentIndex(1)
        aid = item.data(Qt.UserRole)
        self._current_aid = aid
        artifact = ARTIFACT_INDEX[aid]
        self.art_title_lbl.setText(artifact["label"])
        self._configure_filter_bar(aid)
        self.run_btn.setEnabled(self._handler is not None)
        if aid in self._artifact_cache:
            self._display_artifact(aid, self._artifact_cache[aid])
        else:
            self.result_overview.setPlainText(
                f"{artifact['label']}\n\n{artifact['description']}"
            )
            self.result_parsed_table.clear()
            self.result_parsed_table.setRowCount(0)
            self.result_parsed_table.setColumnCount(0)
            self.result_raw.clear()

    def _run_selected_artifact(self):
        if not self._handler or not self._current_aid:
            return
        self.run_btn.setEnabled(False)
        self.run_btn.setText("...")
        if self._current_aid in {"filesystem", "timeline"}:
            self.filesystem_filter_combo.setCurrentIndex(0)
        self.result_overview.setPlainText("Collecting and parsing...")
        self.result_parsed_table.clear()
        self.result_parsed_table.setRowCount(0)
        self.result_parsed_table.setColumnCount(0)
        self.result_raw.clear()

        worker = ArtifactWorker(self._current_aid, self._handler)
        worker.log_msg.connect(self._log)
        worker.log_msg.connect(self._on_worker_log_progress)
        worker.done.connect(self._on_artifact_done)
        worker.error.connect(self._on_artifact_error)
        worker.finished.connect(
            lambda: (self.run_btn.setEnabled(True), self.run_btn.setText("Run"))
        )
        self._show_progress_dialog(f"Running {self.art_title_lbl.text()}", total_steps=0)
        self._keep(worker)
        worker.start()

    def _open_timeline(self):
        if not self._handler:
            self.status.showMessage("Open an image first.")
            return
        cached = self._artifact_cache.get("timeline")
        if cached:
            self._show_timeline_page(cached)
            return
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Question)
        dialog.setWindowTitle("Build Timeline")
        dialog.setText("Build the integrated timeline now?")
        dialog.setInformativeText(
            "This may take some time depending on the image size and artifact count."
        )
        dialog.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        dialog.setDefaultButton(QMessageBox.Yes)
        dialog.setStyleSheet("""
            QMessageBox {
                background: #f5f7fa;
            }
            QMessageBox QLabel {
                color: #1f2933;
                font-size: 10pt;
            }
            QMessageBox QPushButton {
                min-width: 92px;
                min-height: 34px;
                border-radius: 8px;
                padding: 0 14px;
                font-weight: 600;
                border: 1px solid #d7dee7;
                background: #ffffff;
                color: #1f2933;
            }
            QMessageBox QPushButton:hover {
                background: #eef2f7;
            }
        """)
        yes_button = dialog.button(QMessageBox.Yes)
        if yes_button is not None:
            yes_button.setText("Build")
            yes_button.setStyleSheet("""
                min-width: 92px;
                min-height: 34px;
                border-radius: 8px;
                padding: 0 14px;
                font-weight: 600;
                border: none;
                background: #2563eb;
                color: white;
            """)
        no_button = dialog.button(QMessageBox.No)
        if no_button is not None:
            no_button.setText("Cancel")
            no_button.setStyleSheet("""
                min-width: 92px;
                min-height: 34px;
                border-radius: 8px;
                padding: 0 14px;
                font-weight: 600;
                border: 1px solid #d7dee7;
                background: #eef2f7;
                color: #475569;
            """)
        if dialog.exec_() != QMessageBox.Yes:
            self.status.showMessage("Timeline build cancelled.")
            return
        self.act_timeline.setEnabled(False)
        self.status.showMessage("Building integrated timeline...")
        worker = ArtifactWorker("timeline", self._handler, artifact_cache=dict(self._artifact_cache))
        worker.log_msg.connect(self._log)
        worker.log_msg.connect(self._on_worker_log_progress)
        worker.done.connect(self._on_timeline_done)
        worker.error.connect(self._on_artifact_error)
        worker.finished.connect(lambda: self.act_timeline.setEnabled(self._handler is not None))
        total_steps = max(1, len([a for a in ARTIFACT_REGISTRY if a["id"] != "timeline"]))
        self._show_progress_dialog("Building Timeline", total_steps=total_steps)
        self._keep(worker)
        worker.start()

    def _on_timeline_done(self, aid: str, entries: list):
        self._artifact_cache[aid] = entries
        self._show_timeline_page(entries)
        QApplication.processEvents()
        self._finish_progress_dialog("Timeline ready")

    def _show_timeline_page(self, entries: list):
        if self._timeline_entries_ref is not entries:
            self.timeline_page_widget.set_events(entries)
            self._timeline_entries_ref = entries
        self.main_pages.setCurrentIndex(self._ensure_timeline_tab())
        self.status.showMessage(f"timeline: {len(entries)} entries")

    def _ensure_timeline_tab(self) -> int:
        if self._timeline_tab_index is not None:
            return self._timeline_tab_index
        self._timeline_tab_index = self.main_pages.addTab(self.timeline_page, "Timeline")
        return self._timeline_tab_index

    def _close_main_tab(self, index: int) -> None:
        if index <= 0:
            return
        widget = self.main_pages.widget(index)
        self.main_pages.removeTab(index)
        if widget is self.timeline_page:
            self._timeline_tab_index = None
            self.main_pages.setCurrentIndex(0)

    def _on_artifact_done(self, aid: str, entries: list):
        self._artifact_cache[aid] = entries
        if aid != "timeline":
            self._artifact_cache.pop("timeline", None)
            self._timeline_entries_ref = None
        self._finish_progress_dialog(f"{aid} completed")
        self.main_pages.setCurrentIndex(0)
        self._display_artifact(aid, entries)
        self.act_export.setEnabled(bool(entries))

    def _on_artifact_error(self, msg: str):
        self._log(msg)
        self._finish_progress_dialog(msg)
        self.result_overview.setPlainText(msg)
        self.result_parsed_table.clear()
        self.result_parsed_table.setRowCount(0)
        self.result_parsed_table.setColumnCount(0)
        self.result_raw.clear()

    def _on_filesystem_filter_changed(self, _index: int):
        if self._current_aid not in {"filesystem", "timeline"}:
            return
        entries = self._artifact_cache.get(self._current_aid)
        if entries is not None:
            self._display_artifact(self._current_aid, entries)

    # ═══════════════════════════════════════════════════════
    # 아티팩트 표시
    # ═══════════════════════════════════════════════════════

    def _display_artifact(self, aid: str, entries: list):
        filter_text     = self.filesystem_filter_combo.currentText() or "All"
        filtered        = ac.apply_filter(aid, entries, filter_text)
        self._current_filtered_entries = filtered

        if not filtered:
            self.result_overview.setPlainText("No entries were collected.")
            self.result_parsed_table.clear()
            self.result_parsed_table.setRowCount(0)
            self.result_parsed_table.setColumnCount(0)
            self.result_raw.clear()
            return

        artifact = ARTIFACT_INDEX[aid]
        overview_lines = [
            artifact["label"], "",
            artifact["description"],
            f"Entries: {len(filtered)} / {len(entries)}",
        ]
        if aid in {"filesystem", "timeline"}:
            overview_lines.append(f"Filter: {filter_text}")
        self.result_overview.setPlainText("\n".join(overview_lines))

        self._populate_parsed_table(aid, filtered)

        visible_raw = filtered[:_MAX_RAW_JSON_ROWS]
        sanitized = [self._sanitize_entry(e) for e in visible_raw]
        raw_text = json.dumps(
            sanitized, default=self._json_default, ensure_ascii=False, indent=2
        )
        if len(filtered) > len(visible_raw):
            raw_text = (
                f"Showing first {len(visible_raw)} of {len(filtered)} entries in Raw view.\n\n"
                + raw_text
            )
        self.result_raw.setPlainText(raw_text)
        self.result_tabs.setCurrentIndex(0)
        self.status.showMessage(f"{aid}: {len(filtered)} entries")

    def _populate_parsed_table(self, aid: str, entries: list) -> None:
        columns = ac.get_columns(aid)
        self.result_parsed_table.setSortingEnabled(False)
        self.result_parsed_table.clear()
        self.result_parsed_table.setColumnCount(len(columns))
        self.result_parsed_table.setHorizontalHeaderLabels(
            [label for _, label in columns]
        )
        visible = entries[:_MAX_TABLE_ROWS]
        self.result_parsed_table.setRowCount(len(visible))

        for row, entry in enumerate(visible):
            mapped = ac.get_row(aid, entry, self._fmt_size, self._fmt_dt)
            for col, (key, _) in enumerate(columns):
                sort_val = ac.get_sort_value(entry, key, mapped.get(key, ""))
                cell = SortableTableWidgetItem(mapped.get(key, ""), sort_val)
                cell.setForeground(QColor(C_TEXT))
                self.result_parsed_table.setItem(row, col, cell)

        header = self.result_parsed_table.horizontalHeader()
        _STRETCH_KEYS = {"path", "url", "target_path", "description", "decoded_data"}
        for i, (key, _) in enumerate(columns):
            mode = (
                QHeaderView.Stretch
                if key in _STRETCH_KEYS
                else QHeaderView.ResizeToContents
            )
            header.setSectionResizeMode(i, mode)
        self.result_parsed_table.setSortingEnabled(True)

    # ═══════════════════════════════════════════════════════
    # 내보내기
    # ═══════════════════════════════════════════════════════

    def _export_results(self):
        if not self._current_aid:
            return
        default_name = f"{self._current_aid}_result.txt"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Result", default_name, "Text Files (*.txt)"
        )
        if not path:
            return
        aid      = self._current_aid
        entries  = self._artifact_cache.get(aid, [])
        artifact = ARTIFACT_INDEX[aid]
        text = ac.export_text(
            aid, entries,
            artifact["label"], artifact["description"],
            self.filesystem_filter_combo.currentText() or "All",
            self._fmt_size, self._fmt_dt,
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        self._log(f"[INFO] exported result: {path}")

    def _configure_filter_bar(self, aid: str) -> None:
        if aid == "filesystem":
            self.filesystem_filter_label.setText("MFT Filter")
            self._set_filter_options([
                "All",
                "Recycle Bin Only",
                "Document Extensions Only",
                "Recent 24 Hours",
            ])
            self.filesystem_filter_bar.setVisible(True)
            return
        if aid == "timeline":
            self.filesystem_filter_label.setText("Timeline Filter")
            self._set_filter_options([
                "All",
                "File Activity",
                "Web Activity",
                "USB Activity",
                "Mail Activity",
                "Execution Activity",
            ])
            self.filesystem_filter_bar.setVisible(True)
            return
        self.filesystem_filter_bar.setVisible(False)

    def _set_filter_options(self, options: list[str]) -> None:
        self.filesystem_filter_combo.blockSignals(True)
        self.filesystem_filter_combo.clear()
        self.filesystem_filter_combo.addItems(options)
        self.filesystem_filter_combo.setCurrentIndex(0)
        self.filesystem_filter_combo.blockSignals(False)

    def _show_progress_dialog(self, title: str, total_steps: int) -> None:
        self._finish_progress_dialog()
        self._progress_dialog = ProgressDialog(title, total_steps=total_steps, parent=self)
        self._progress_dialog.show()
        self._progress_dialog.raise_()

    def _on_worker_log_progress(self, message: str) -> None:
        if self._progress_dialog is not None:
            self._progress_dialog.update_from_log(message)

    def _finish_progress_dialog(self, message: Optional[str] = None) -> None:
        if self._progress_dialog is None:
            return
        if message:
            self._progress_dialog.complete(message)
            QApplication.processEvents()
        self._progress_dialog.close()
        self._progress_dialog.deleteLater()
        self._progress_dialog = None

    # ═══════════════════════════════════════════════════════
    # 유틸리티
    # ═══════════════════════════════════════════════════════

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_output.append(f"[{ts}] {msg}")

    def _on_error(self, msg: str):
        self._log(msg)
        self.status.showMessage(msg)
        self._pending_image_path = None

    def _keep(self, worker):
        self._workers.append(worker)
        worker.finished.connect(
            lambda: self._workers.remove(worker) if worker in self._workers else None
        )
    def closeEvent(self, event):
        for worker in list(self._workers):
            if worker.isRunning():
                worker.quit()
                worker.wait(2000)
        event.accept()

    @staticmethod
    def _sanitize_entry(entry: dict) -> dict:
        if not isinstance(entry, dict):
            return entry
        return {k: v for k, v in entry.items() if k != "artifact_weight"}

    @staticmethod
    def _fmt_size(size) -> str:
        if size is None:
            return "?"
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    @staticmethod
    def _ext(name: str) -> str:
        ext = os.path.splitext(name)[1].lower()
        return ext.lstrip(".").upper() if ext else "FILE"

    @staticmethod
    def _fmt_dt(value) -> str:
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
