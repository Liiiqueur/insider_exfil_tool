import os
import tempfile
import logging
from datetime import datetime, timezone

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTextEdit, QLabel, QFileDialog, QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QTabWidget, QToolBar, QAction,
    QHeaderView, QStatusBar, QAbstractItemView, QListWidget,
    QListWidgetItem, QPushButton, QFrame,
)
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from image_handler import ImageHandler
from collectors import userassist_collector
from parsers import userassist_parser
from collectors import jumplist_collector
from parsers import jumplist_parser

logger = logging.getLogger(__name__)

# ── 색상 팔레트 ───────────────────────────────────────────────────────────────
C_BG      = "#f5f7fa"
C_PANEL   = "#ffffff"
C_BORDER  = "#e1e5ea"
C_HEADER  = "#eef2f7"
C_TEXT    = "#1f2933"
C_SUBTEXT = "#6b7280"
C_SELECT  = "#e6f0ff"
C_BLUE    = "#2563eb"
C_AMBER   = "#f59e0b"
C_GREEN   = "#059669"
C_RED     = "#dc2626"
C_PURPLE  = "#7c3aed"


# ── 아티팩트 정의 레지스트리 ──────────────────────────────────────────────────
# 새 아티팩트 추가 시 이 목록에 항목만 추가하면 됨
ARTIFACT_REGISTRY = [
    {
        "id":          "userassist",
        "label":       "UserAssist",
        "icon":        "⚙",
        "description": "사용자가 실행한 프로그램 기록\n(NTUSER.DAT → UserAssist 레지스트리)",
        "color":       C_BLUE,
    },
    {
        "id":          "jumplist",
        "label":       "Jumplist",
        "icon":        "🔗",
        "description": "최근·자주 사용한 파일/프로그램 목록\n(AutomaticDestinations / CustomDestinations)",
        "color":       C_PURPLE,
    },
    # 추후 추가 예시:
    # {"id": "shellbags",   "label": "Shellbags",      "icon": "🗂", ...},
    # {"id": "prefetch",    "label": "Prefetch",        "icon": "📋", ...},
    # {"id": "eventlog",    "label": "Event Log",       "icon": "📋", ...},
    # {"id": "browserhistory", "label": "Browser History", "icon": "🌐", ...},
]


# ── 백그라운드 워커 ───────────────────────────────────────────────────────────

class LoadImageWorker(QThread):
    done    = pyqtSignal(object)
    log_msg = pyqtSignal(str)
    error   = pyqtSignal(str)

    def __init__(self, path):
        super().__init__()
        self.path = path

    def run(self):
        try:
            self.log_msg.emit(f"[INFO] 이미지 열기: {self.path}")
            handler = ImageHandler()
            handler.open(self.path)
            if not handler.volumes:
                self.error.emit("[ERROR] 볼륨을 찾지 못했습니다. 이미지 포맷을 확인하세요.")
                return
            self.log_msg.emit(f"[INFO] 볼륨 {len(handler.volumes)}개 발견")
            self.done.emit(handler)
        except Exception as e:
            self.error.emit(f"[ERROR] 이미지 열기 실패: {e}")


class ListDirWorker(QThread):
    done    = pyqtSignal(list, object)
    log_msg = pyqtSignal(str)
    error   = pyqtSignal(str)

    def __init__(self, handler, fs, inode, path, tree_item):
        super().__init__()
        self.handler, self.fs = handler, fs
        self.inode, self.path = inode, path
        self.tree_item = tree_item

    def run(self):
        try:
            entries = self.handler.list_directory(self.fs, self.inode, self.path)
            self.done.emit(entries, self.tree_item)
        except Exception as e:
            self.error.emit(f"[ERROR] 디렉터리 읽기 실패: {e}")


class ArtifactWorker(QThread):
    """단일 아티팩트 ID를 받아 해당 수집·파싱만 수행."""
    done    = pyqtSignal(str, list)   # (artifact_id, entries)
    log_msg = pyqtSignal(str)
    error   = pyqtSignal(str)

    def __init__(self, artifact_id: str, handler: ImageHandler):
        super().__init__()
        self.artifact_id = artifact_id
        self.handler     = handler

    def run(self):
        aid = self.artifact_id
        try:
            if aid == "userassist":
                entries = self._run_userassist()
            elif aid == "jumplist":
                entries = self._run_jumplist()
            else:
                self.error.emit(f"[ERROR] 알 수 없는 아티팩트: {aid}")
                return
            self.log_msg.emit(f"[INFO] {aid} 파싱 완료 – {len(entries)}건")
            self.done.emit(aid, entries)
        except Exception as e:
            self.error.emit(f"[ERROR] {aid} 수집 실패: {e}")

    def _run_userassist(self) -> list:
        all_entries = []
        for vol in self.handler.volumes:
            fs = vol["fs"]
            self.log_msg.emit(f"[INFO] [{vol['desc']}] NTUSER.DAT 탐색...")
            for hive in self.handler.find_ntuser_dat(fs):
                self.log_msg.emit(f"[INFO] 하이브: {hive['path']}")
                raw_data = self.handler.read_file(fs, hive["inode"], 50 * 1024 * 1024)
                if not raw_data:
                    continue
                with tempfile.NamedTemporaryFile(suffix="_NTUSER.DAT", delete=False) as tmp:
                    tmp.write(raw_data)
                    tmp_path = tmp.name
                try:
                    raw = userassist_collector.collect(tmp_path)
                    all_entries.extend(userassist_parser.parse(raw))
                finally:
                    os.unlink(tmp_path)
        return all_entries

    def _run_jumplist(self) -> list:
        all_collected = []
        for vol in self.handler.volumes:
            fs = vol["fs"]
            self.log_msg.emit(f"[INFO] [{vol['desc']}] Jumplist 탐색...")
            collected = jumplist_collector.collect_from_image(self.handler, fs)
            all_collected.extend(collected)
        self.log_msg.emit(f"[INFO] Jumplist 파일 {len(all_collected)}개 수집")
        entries = jumplist_parser.parse(all_collected)
        # 임시 파일 정리
        for info in all_collected:
            try:
                if os.path.exists(info["tmp_path"]):
                    os.unlink(info["tmp_path"])
            except Exception:
                pass
        return entries


# ── 메인 윈도우 ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Insider Exfiltration Tool")
        self.setGeometry(100, 100, 1500, 900)
        self.setMinimumSize(1100, 650)

        self._handler        = None
        self._workers        = []
        self._item_meta      = {}
        self._table_entries  = []
        self._table_fs       = None
        self._artifact_cache = {}   # {artifact_id: entries}
        self._current_aid    = None

        self._init_ui()
        self._apply_style()

    # ── UI 구성 ───────────────────────────────────────────────────────────────

    def _init_ui(self):
        # ── 툴바
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)

        act_open = QAction("📂  이미지 열기", self)
        act_open.triggered.connect(self._open_image)

        self.act_export = QAction("💾  결과 내보내기", self)
        self.act_export.setEnabled(False)
        self.act_export.triggered.connect(self._export_results)

        toolbar.addAction(act_open)
        toolbar.addSeparator()
        toolbar.addAction(self.act_export)

        # ── 패널 1: Evidence Tree (좌)
        left_panel = self._make_evidence_tree()

        # ── 패널 2: 파일 브라우저 + Hex/Text 뷰어 (중)
        mid_panel = self._make_file_browser()

        # ── 패널 3: 아티팩트 (우)
        right_panel = self._make_artifact_panel()

        # ── 3단 스플리터
        main_split = QSplitter(Qt.Horizontal)
        main_split.addWidget(left_panel)
        main_split.addWidget(mid_panel)
        main_split.addWidget(right_panel)
        main_split.setSizes([250, 700, 500])
        main_split.setStretchFactor(1, 2)

        # ── 로그
        log_panel = QWidget()
        logv = QVBoxLayout(log_panel)
        logv.setContentsMargins(4, 0, 4, 2)
        logv.setSpacing(0)
        log_lbl = QLabel("  로그")
        log_lbl.setFixedHeight(20)
        log_lbl.setObjectName("log_header")
        logv.addWidget(log_lbl)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFixedHeight(110)
        self.log_output.setFont(QFont("Consolas", 9))
        logv.addWidget(self.log_output)

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
        self.status.showMessage("이미지를 열어 분석을 시작하세요.")

    def _make_evidence_tree(self) -> QWidget:
        panel = QWidget()
        lv = QVBoxLayout(panel)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(0)

        lbl = QLabel("  Evidence Tree")
        lbl.setFixedHeight(28)
        lbl.setObjectName("panel_header")
        lv.addWidget(lbl)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemExpanded.connect(self._on_tree_expanded)
        self.tree.itemClicked.connect(self._on_tree_clicked)
        lv.addWidget(self.tree)
        return panel

    def _make_file_browser(self) -> QWidget:
        # 파일 목록
        file_panel = QWidget()
        fv = QVBoxLayout(file_panel)
        fv.setContentsMargins(0, 0, 0, 0)
        fv.setSpacing(0)
        flbl = QLabel("  파일 목록")
        flbl.setFixedHeight(28)
        flbl.setObjectName("panel_header")
        fv.addWidget(flbl)

        self.file_table = QTableWidget()
        self.file_table.setColumnCount(4)
        self.file_table.setHorizontalHeaderLabels(["이름", "크기", "유형", "Inode"])
        self.file_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.file_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.file_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.file_table.verticalHeader().setVisible(False)
        self.file_table.setShowGrid(True)
        self.file_table.itemClicked.connect(self._on_file_clicked)
        fv.addWidget(self.file_table)

        # Hex / Text 뷰어 탭
        viewer_tabs = QTabWidget()
        viewer_tabs.setObjectName("viewer_tabs")

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Consolas", 10))

        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.text_view.setFont(QFont("Consolas", 10))

        viewer_tabs.addTab(self.hex_view, "Hex")
        viewer_tabs.addTab(self.text_view, "Text")

        mid_split = QSplitter(Qt.Vertical)
        mid_split.addWidget(file_panel)
        mid_split.addWidget(viewer_tabs)
        mid_split.setSizes([400, 260])
        return mid_split

    def _make_artifact_panel(self) -> QWidget:
        """
        우측 아티팩트 패널.
        상단: 아티팩트 목록 (QListWidget)
        하단: 선택된 아티팩트 결과 (QTextEdit)
        """
        panel = QWidget()
        pv = QVBoxLayout(panel)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.setSpacing(0)

        # ── 헤더
        lbl = QLabel("  아티팩트")
        lbl.setFixedHeight(28)
        lbl.setObjectName("panel_header")
        pv.addWidget(lbl)

        # ── 아티팩트 목록
        self.artifact_list = QListWidget()
        self.artifact_list.setFixedHeight(len(ARTIFACT_REGISTRY) * 52 + 8)
        self.artifact_list.setSpacing(2)

        for art in ARTIFACT_REGISTRY:
            item = QListWidgetItem(f"  {art['icon']}  {art['label']}")
            item.setData(Qt.UserRole, art["id"])
            item.setToolTip(art["description"])
            item.setFont(QFont("Malgun Gothic", 11))
            self.artifact_list.addItem(item)

        self.artifact_list.itemClicked.connect(self._on_artifact_clicked)
        pv.addWidget(self.artifact_list)

        # ── 구분선
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setObjectName("divider")
        pv.addWidget(line)

        # ── 아티팩트 정보 헤더 (선택된 아티팩트명 + 실행 버튼)
        info_bar = QWidget()
        info_lay = QHBoxLayout(info_bar)
        info_lay.setContentsMargins(8, 4, 8, 4)

        self.art_title_lbl = QLabel("아티팩트를 선택하세요")
        self.art_title_lbl.setObjectName("art_title")
        info_lay.addWidget(self.art_title_lbl, stretch=1)

        self.run_btn = QPushButton("▶  추출")
        self.run_btn.setObjectName("run_btn")
        self.run_btn.setFixedWidth(72)
        self.run_btn.setEnabled(False)
        self.run_btn.clicked.connect(self._run_selected_artifact)
        info_lay.addWidget(self.run_btn)

        pv.addWidget(info_bar)

        # ── 결과 영역 (탭: 요약 | 원시)
        self.result_tabs = QTabWidget()
        self.result_tabs.setObjectName("result_tabs")

        self.result_summary = QTextEdit()
        self.result_summary.setReadOnly(True)
        self.result_summary.setFont(QFont("Consolas", 10))
        self.result_summary.setPlaceholderText("아티팩트를 선택하고 ▶ 추출을 클릭하세요.")

        self.result_raw = QTextEdit()
        self.result_raw.setReadOnly(True)
        self.result_raw.setFont(QFont("Consolas", 9))

        self.result_tabs.addTab(self.result_summary, "요약")
        self.result_tabs.addTab(self.result_raw,     "원시 데이터")

        pv.addWidget(self.result_tabs, stretch=1)
        return panel

    # ── 이미지 열기 ───────────────────────────────────────────────────────────

    def _open_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "이미지 파일 선택", "",
            "Forensic Images (*.E01 *.e01 *.dd *.raw *.img);;All Files (*)"
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

        w = LoadImageWorker(path)
        w.log_msg.connect(self._log)
        w.done.connect(self._on_image_loaded)
        w.error.connect(self._on_error)
        self._keep(w)
        w.start()

    def _on_image_loaded(self, handler):
        self._handler = handler
        self.status.showMessage(f"이미지: {os.path.basename(handler.image_path)}")
        self._log(f"[INFO] 이미지 로드 완료 – 볼륨 {len(handler.volumes)}개")

        img_item = QTreeWidgetItem([f"🖴  {os.path.basename(handler.image_path)}"])
        img_item.setForeground(0, QColor(C_AMBER))
        self.tree.addTopLevelItem(img_item)

        for vol in handler.volumes:
            vol_item = QTreeWidgetItem([f"📦  {vol['desc']}"])
            vol_item.setForeground(0, QColor(C_BLUE))
            self._item_meta[id(vol_item)] = {
                "fs": vol["fs"], "inode": None, "path": "/", "is_dir": True
            }
            vol_item.addChild(QTreeWidgetItem(["로딩 중..."]))
            img_item.addChild(vol_item)

        img_item.setExpanded(True)

        # 이미지 로드 후 아티팩트 목록 활성화
        self.run_btn.setEnabled(self._current_aid is not None)
        for i in range(self.artifact_list.count()):
            self.artifact_list.item(i).setFlags(
                Qt.ItemIsEnabled | Qt.ItemIsSelectable
            )

    # ── Evidence Tree ─────────────────────────────────────────────────────────

    def _on_tree_expanded(self, item):
        meta = self._item_meta.get(id(item))
        if not meta:
            return
        if item.childCount() == 1 and item.child(0).text(0) == "로딩 중...":
            item.takeChildren()
            w = ListDirWorker(
                self._handler, meta["fs"], meta["inode"], meta["path"], item
            )
            w.log_msg.connect(self._log)
            w.done.connect(self._on_dir_loaded)
            w.error.connect(self._on_error)
            self._keep(w)
            w.start()

    def _on_dir_loaded(self, entries, parent_item):
        for e in entries:
            icon = "📁" if e.is_dir else self._file_icon(e.name)
            child = QTreeWidgetItem([f"{icon}  {e.name}"])
            child.setForeground(0, QColor(C_AMBER if e.is_dir else C_TEXT))
            self._item_meta[id(child)] = {
                "fs": self._item_meta[id(parent_item)]["fs"],
                "inode": e.inode, "path": e.path, "is_dir": e.is_dir,
            }
            if e.is_dir:
                child.addChild(QTreeWidgetItem(["로딩 중..."]))
            parent_item.addChild(child)

    def _on_tree_clicked(self, item):
        meta = self._item_meta.get(id(item))
        if not meta or not meta["is_dir"]:
            return
        w = ListDirWorker(
            self._handler, meta["fs"], meta["inode"], meta["path"], item
        )
        w.log_msg.connect(self._log)
        w.done.connect(self._populate_file_table)
        w.error.connect(self._on_error)
        self._keep(w)
        w.start()

    # ── 파일 테이블 ───────────────────────────────────────────────────────────

    def _populate_file_table(self, entries, _item=None):
        self._table_entries = entries
        self._table_fs = self._item_meta.get(
            id(self.tree.currentItem()), {}
        ).get("fs")
        self.file_table.setRowCount(0)
        for row, e in enumerate(entries):
            self.file_table.insertRow(row)
            icon = "📁 " if e.is_dir else self._file_icon(e.name) + " "
            cells = [
                QTableWidgetItem(icon + e.name),
                QTableWidgetItem("" if e.is_dir else self._fmt_size(e.size)),
                QTableWidgetItem("폴더" if e.is_dir else self._ext(e.name)),
                QTableWidgetItem(str(e.inode)),
            ]
            for col, ci in enumerate(cells):
                ci.setForeground(QColor(C_TEXT))
                self.file_table.setItem(row, col, ci)

    def _on_file_clicked(self, item):
        row = item.row()
        if row >= len(self._table_entries):
            return
        e = self._table_entries[row]
        if e.is_dir or not self._table_fs:
            return
        data = self._handler.read_file(self._table_fs, e.inode, max_bytes=64 * 1024)
        self._show_hex(data)
        self._show_text(data)
        self.status.showMessage(f"{e.path}  ({self._fmt_size(e.size)})")

    def _show_hex(self, data: bytes):
        lines = []
        for i in range(0, min(len(data), 4096), 16):
            chunk = data[i:i + 16]
            hex_part  = " ".join(f"{b:02X}" for b in chunk)
            text_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08X}  {hex_part:<48}  {text_part}")
        self.hex_view.setPlainText("\n".join(lines))

    def _show_text(self, data: bytes):
        self.text_view.setPlainText(data.decode("utf-8", errors="replace")[:8192])

    # ── 아티팩트 패널 ─────────────────────────────────────────────────────────

    def _on_artifact_clicked(self, item: QListWidgetItem):
        aid = item.data(Qt.UserRole)
        self._current_aid = aid

        art = next(a for a in ARTIFACT_REGISTRY if a["id"] == aid)
        self.art_title_lbl.setText(f"{art['icon']}  {art['label']}")

        # 이미지가 로드된 경우만 추출 버튼 활성화
        self.run_btn.setEnabled(self._handler is not None)

        # 캐시된 결과가 있으면 바로 표시
        if aid in self._artifact_cache:
            self._display_artifact(aid, self._artifact_cache[aid])
        else:
            self.result_summary.setPlainText(
                f"▶ 추출 버튼을 눌러 {art['label']} 데이터를 수집합니다.\n\n"
                f"{art['description']}"
            )
            self.result_raw.clear()

    def _run_selected_artifact(self):
        if not self._handler or not self._current_aid:
            return

        self.run_btn.setEnabled(False)
        self.run_btn.setText("⏳")
        self.result_summary.setPlainText("수집 중...")
        self.result_raw.clear()

        w = ArtifactWorker(self._current_aid, self._handler)
        w.log_msg.connect(self._log)
        w.done.connect(self._on_artifact_done)
        w.error.connect(self._on_artifact_error)
        w.finished.connect(lambda: (
            self.run_btn.setEnabled(True),
            self.run_btn.setText("▶  추출"),
        ))
        self._keep(w)
        w.start()

    def _on_artifact_done(self, aid: str, entries: list):
        self._artifact_cache[aid] = entries
        self._display_artifact(aid, entries)
        self.act_export.setEnabled(bool(entries))

    def _on_artifact_error(self, msg: str):
        self._log(msg)
        self.result_summary.setPlainText(msg)

    def _display_artifact(self, aid: str, entries: list):
        """aid에 따라 포맷된 요약과 원시 데이터를 결과 탭에 표시."""
        if not entries:
            self.result_summary.setPlainText("수집된 항목이 없습니다.")
            self.result_raw.setPlainText("")
            return

        if aid == "userassist":
            summary, raw = self._format_userassist(entries)
        elif aid == "jumplist":
            summary, raw = self._format_jumplist(entries)
        else:
            summary = str(entries)
            raw = summary

        self.result_summary.setPlainText(summary)
        self.result_raw.setPlainText(raw)
        self.result_tabs.setCurrentIndex(0)
        self.status.showMessage(f"{aid} – {len(entries)}건")

    # ── 아티팩트별 포맷터 ─────────────────────────────────────────────────────

    def _format_userassist(self, entries: list) -> tuple[str, str]:
        lines = [
            "=" * 64,
            f"  UserAssist  –  총 {len(entries)}건",
            "=" * 64, "",
        ]
        raw_lines = list(lines)

        for e in entries:
            ts = (e["last_run_time"].strftime("%Y-%m-%d %H:%M:%S UTC")
                  if e["last_run_time"] else "알 수 없음")
            name = e["name"] or "(이름 없음)"
            lines += [
                f"[{e['guid_type']}]  {name}",
                f"  사용자: {e.get('username','?')}  |  "
                f"실행 횟수: {e['run_count']}  |  "
                f"세션: {e['session_id']}  |  "
                f"마지막 실행: {ts}",
                "",
            ]
            raw_lines.append(str(e))

        return "\n".join(lines), "\n".join(raw_lines)

    def _format_jumplist(self, entries: list) -> tuple[str, str]:
        lines = [
            "=" * 64,
            f"  Jumplist  –  총 {len(entries)}건",
            "=" * 64, "",
        ]
        raw_lines = list(lines)

        for e in entries:
            ts = (e["access_time"].strftime("%Y-%m-%d %H:%M:%S UTC")
                  if e.get("access_time") else "알 수 없음")
            path = e.get("target_path") or e.get("name") or "(경로 없음)"
            lines += [
                f"[{e['category']}]  {e['appname']} ({e['appid']})",
                f"  경로: {path}",
                f"  사용자: {e.get('username','?')}  |  "
                f"접근 횟수: {e.get('access_count', 0)}  |  "
                f"마지막 접근: {ts}",
                "",
            ]
            raw_lines.append(str(e))

        return "\n".join(lines), "\n".join(raw_lines)

    # ── 결과 내보내기 ─────────────────────────────────────────────────────────

    def _export_results(self):
        if not self._current_aid:
            return
        art = next((a for a in ARTIFACT_REGISTRY if a["id"] == self._current_aid), None)
        default_name = f"{self._current_aid}_result.txt"
        path, _ = QFileDialog.getSaveFileName(
            self, "결과 저장", default_name, "Text Files (*.txt)"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.result_summary.toPlainText())
            self._log(f"[INFO] 저장 완료: {path}")

    # ── 유틸 ─────────────────────────────────────────────────────────────────

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_output.append(f"[{ts}] {msg}")

    def _on_error(self, msg: str):
        self._log(msg)
        self.status.showMessage(msg)

    def _keep(self, w):
        self._workers.append(w)
        w.finished.connect(
            lambda: self._workers.remove(w) if w in self._workers else None
        )

    @staticmethod
    def _fmt_size(size):
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    @staticmethod
    def _ext(name):
        ext = os.path.splitext(name)[1].lower()
        return ext.lstrip(".").upper() if ext else "파일"

    @staticmethod
    def _file_icon(name):
        icons = {
            ".exe": "⚙", ".dll": "⚙", ".sys": "⚙",
            ".txt": "📄", ".log": "📄", ".csv": "📄",
            ".dat": "🗃", ".db": "🗃", ".sqlite": "🗃",
            ".lnk": "🔗", ".pf": "📋",
            ".jpg": "🖼", ".png": "🖼",
            ".zip": "🗜", ".rar": "🗜",
        }
        return icons.get(os.path.splitext(name)[1].lower(), "📄")

    # ── 스타일 ────────────────────────────────────────────────────────────────

    def _apply_style(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {C_BG};
                color: {C_TEXT};
                font-family: 'Malgun Gothic', 'Segoe UI', sans-serif;
                font-size: 12px;
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
                font-size: 12px;
            }}
            QToolBar QToolButton:hover {{
                background: {C_SELECT};
                color: {C_BLUE};
            }}
            QToolBar QToolButton:disabled {{ color: {C_SUBTEXT}; }}

            QLabel#panel_header {{
                background: {C_HEADER};
                color: {C_BLUE};
                font-weight: bold;
                font-size: 11px;
                padding-left: 8px;
                border-bottom: 1px solid {C_BORDER};
            }}
            QLabel#log_header {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                font-size: 10px;
                padding-left: 8px;
            }}
            QLabel#art_title {{
                font-weight: bold;
                font-size: 12px;
                color: {C_TEXT};
            }}

            /* Evidence Tree */
            QTreeWidget {{
                background: {C_PANEL};
                border: none;
                border-right: 1px solid {C_BORDER};
            }}
            QTreeWidget::item {{ padding: 2px 0; }}
            QTreeWidget::item:selected {{ background: {C_SELECT}; color: {C_BLUE}; }}
            QTreeWidget::item:hover    {{ background: {C_SELECT}; }}

            /* 파일 테이블 */
            QTableWidget {{
                background: {C_PANEL};
                border: none;
                gridline-color: {C_BORDER};
            }}
            QTableWidget::item {{ padding: 2px 4px; }}
            QTableWidget::item:selected {{ background: {C_SELECT}; color: {C_BLUE}; }}
            QHeaderView::section {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                border: none;
                border-bottom: 1px solid {C_BORDER};
                border-right: 1px solid {C_BORDER};
                padding: 4px 8px;
                font-size: 11px;
            }}

            /* 아티팩트 목록 */
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
            QListWidget::item:selected {{
                background: {C_SELECT};
                color: {C_BLUE};
                font-weight: bold;
            }}
            QListWidget::item:hover {{ background: {C_SELECT}; }}

            /* 추출 버튼 */
            QPushButton#run_btn {{
                background: {C_BLUE};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px 10px;
                font-weight: bold;
                font-size: 11px;
            }}
            QPushButton#run_btn:hover   {{ background: #1d4ed8; }}
            QPushButton#run_btn:disabled {{ background: {C_SUBTEXT}; }}

            /* 뷰어 탭 */
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
            QFrame#divider {{ color: {C_BORDER}; }}

            QScrollBar:vertical {{
                background: {C_BG};
                width: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {C_BORDER};
                border-radius: 4px;
            }}
            QStatusBar {{ background: {C_HEADER}; color: {C_SUBTEXT}; font-size: 11px; }}
            QSplitter::handle {{ background: {C_BORDER}; width: 1px; height: 1px; }}
        """)