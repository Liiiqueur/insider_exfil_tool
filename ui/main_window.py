"""
레이아웃:
  ┌─ 툴바 ──────────────────────────────────────────────────┐
  ├─ 좌(트리) ──────┬─ 우상(파일 목록) ──────────────────────┤
  │  Evidence Tree  │  파일/폴더 테이블                       │
  │  (볼륨·폴더)    ├─ 우하(뷰어) ───────────────────────────┤
  │                 │  탭: Hex | Text | Artifacts             │
  ├─ 로그 ──────────────────────────────────────────────────┤
  └─────────────────────────────────────────────────────────┘
"""

import os
import tempfile
import logging
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QTextEdit, QLabel, QFileDialog, QTreeWidget,
    QTreeWidgetItem, QTableWidget, QTableWidgetItem, QTabWidget,
    QToolBar, QAction, QHeaderView, QStatusBar, QAbstractItemView,
)
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize

from image_handler import ImageHandler
from collectors import userassist_collector
from parsers import userassist_parser

logger = logging.getLogger(__name__)

C_BG      = "#ffffff" 
C_PANEL   = "#f5f7fa" 
C_BORDER  = "#e1e5ea" 
C_HEADER  = "#eef2f7"   
C_TEXT    = "#1f2933"   
C_SUBTEXT = "#6b7280"   
C_SELECT  = "#e6f0ff"  
C_BLUE    = "#2563eb"   
C_AMBER   = "#f59e0b"   
C_GREEN   = "#10b981" 


# ── 워커 ─────────────────────────────────────────────────────────────────────

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
            self.log_msg.emit(f"[INFO] 볼륨 {len(handler.volumes)}개 발견")
            self.done.emit(handler)
        except ValueError as e:
            # E01 포맷 등 지원 안 되는 포맷
            self.error.emit(f"[ERROR] 지원하지 않는 포맷: {e}")
        except RuntimeError as e:
            # FS 탐지 실패
            self.error.emit(f"[ERROR] 파일시스템 탐지 실패: {e}")
        except Exception as e:
            self.error.emit(f"[ERROR] 이미지 열기 실패: {e}")


class ListDirWorker(QThread):
    done    = pyqtSignal(list, object)
    log_msg = pyqtSignal(str)
    error   = pyqtSignal(str)

    def __init__(self, handler, fs, inode, path, tree_item):
        super().__init__()
        self.handler   = handler
        self.fs        = fs
        self.inode     = inode
        self.path      = path
        self.tree_item = tree_item

    def run(self):
        try:
            entries = self.handler.list_directory(self.fs, self.inode, self.path)
            self.done.emit(entries, self.tree_item)
        except Exception as e:
            self.error.emit(f"[ERROR] 디렉터리 읽기 실패: {e}")


class ArtifactWorker(QThread):
    done    = pyqtSignal(list)
    log_msg = pyqtSignal(str)
    error   = pyqtSignal(str)

    def __init__(self, handler):
        super().__init__()
        self.handler = handler

    def run(self):
        try:
            all_entries = []
            for vol in self.handler.volumes:
                fs = vol["fs"]
                self.log_msg.emit(f"[INFO] 볼륨 [{vol['desc']}] NTUSER.DAT 탐색 중...")
                hive_list = self.handler.find_ntuser_dat(fs)

                for hive in hive_list:
                    self.log_msg.emit(f"[INFO] 하이브 발견: {hive['path']}")
                    raw_data = self.handler.read_file(
                        fs, hive["inode"], max_bytes=50 * 1024 * 1024
                    )
                    if not raw_data:
                        continue

                    with tempfile.NamedTemporaryFile(
                        suffix="_NTUSER.DAT", delete=False
                    ) as tmp:
                        tmp.write(raw_data)
                        tmp_path = tmp.name

                    try:
                        raw = userassist_collector.collect(tmp_path)
                        self.log_msg.emit(f"[INFO] {len(raw)}건 수집 ({hive['path']})")
                        entries = userassist_parser.parse(raw)
                        all_entries.extend(entries)
                    finally:
                        os.unlink(tmp_path)

            self.log_msg.emit(f"[INFO] 아티팩트 파싱 완료 – 총 {len(all_entries)}건")
            self.done.emit(all_entries)
        except Exception as e:
            self.error.emit(f"[ERROR] 아티팩트 수집 실패: {e}")


# ── 메인 윈도우 ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Insider Exfilation Tool")
        self.setGeometry(100, 100, 1400, 860)
        self.setMinimumSize(1000, 600)

        self._handler       = None
        self._workers       = []
        self._item_meta     = {}   # id(QTreeWidgetItem) → {fs, inode, path, is_dir}
        self._table_entries = []

        self._init_ui()
        self._apply_style()

    # ── UI 구성 ───────────────────────────────────────────────────────────────

    def _init_ui(self):
        # 툴바
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)

        self.act_open = QAction("📂  이미지 열기", self)
        self.act_open.triggered.connect(self._open_image)

        self.act_artifact = QAction("🔍  아티팩트 추출", self)
        self.act_artifact.setEnabled(False)
        self.act_artifact.triggered.connect(self._extract_artifacts)

        self.act_export = QAction("💾  결과 내보내기", self)
        self.act_export.setEnabled(False)
        self.act_export.triggered.connect(self._export_results)

        toolbar.addAction(self.act_open)
        toolbar.addSeparator()
        toolbar.addAction(self.act_artifact)
        toolbar.addSeparator()
        toolbar.addAction(self.act_export)

        # 좌측 Evidence Tree
        left_panel = QWidget()
        lv = QVBoxLayout(left_panel)
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

        # 우상 파일 목록
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

        # 우하 뷰어 탭
        self.viewer_tabs = QTabWidget()
        self.viewer_tabs.setObjectName("viewer_tabs")

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Consolas", 10))

        self.text_view = QTextEdit()
        self.text_view.setReadOnly(True)
        self.text_view.setFont(QFont("Consolas", 10))

        self.artifact_view = QTextEdit()
        self.artifact_view.setReadOnly(True)
        self.artifact_view.setFont(QFont("Consolas", 10))

        self.viewer_tabs.addTab(self.hex_view, "Hex")
        self.viewer_tabs.addTab(self.text_view, "Text")
        self.viewer_tabs.addTab(self.artifact_view, "Artifacts")

        # 우측 상하 스플리터
        right_split = QSplitter(Qt.Vertical)
        right_split.addWidget(file_panel)
        right_split.addWidget(self.viewer_tabs)
        right_split.setSizes([380, 280])

        # 좌우 메인 스플리터
        main_split = QSplitter(Qt.Horizontal)
        main_split.addWidget(left_panel)
        main_split.addWidget(right_split)
        main_split.setSizes([280, 1120])

        # 로그
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
        self.log_output.setFixedHeight(120)
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

    # ── 이미지 열기 ───────────────────────────────────────────────────────────

    def _open_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "이미지 파일 선택", "",
            # E01 제거, dd / raw / img 만 허용
            "Forensic Images (*.dd *.raw *.img);;All Files (*)"
        )
        if not path:
            return
        self.tree.clear()
        self.file_table.setRowCount(0)
        self.hex_view.clear()
        self.text_view.clear()
        self.artifact_view.clear()
        self._item_meta.clear()
        self.act_artifact.setEnabled(False)
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
        self.act_artifact.setEnabled(True)

    # ── 트리 확장 / 클릭 ─────────────────────────────────────────────────────

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
                "fs":    self._item_meta[id(parent_item)]["fs"],
                "inode": e.inode,
                "path":  e.path,
                "is_dir": e.is_dir,
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
        if e.is_dir or not hasattr(self, "_table_fs") or not self._table_fs:
            return
        data = self._handler.read_file(self._table_fs, e.inode, max_bytes=64 * 1024)
        self._show_hex(data)
        self._show_text(data)
        self.status.showMessage(f"{e.path}  ({self._fmt_size(e.size)})")

    # ── 뷰어 ─────────────────────────────────────────────────────────────────

    def _show_hex(self, data: bytes):
        lines = []
        for i in range(0, min(len(data), 4096), 16):
            chunk = data[i:i + 16]
            hex_part  = " ".join(f"{b:02X}" for b in chunk)
            text_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08X}  {hex_part:<48}  {text_part}")
        self.hex_view.setPlainText("\n".join(lines))
        self.viewer_tabs.setCurrentIndex(0)

    def _show_text(self, data: bytes):
        text = data.decode("utf-8", errors="replace")
        self.text_view.setPlainText(text[:8192])

    # ── 아티팩트 추출 ─────────────────────────────────────────────────────────

    def _extract_artifacts(self):
        if not self._handler:
            return
        self.act_artifact.setEnabled(False)
        self.artifact_view.clear()
        self.viewer_tabs.setCurrentIndex(2)

        w = ArtifactWorker(self._handler)
        w.log_msg.connect(self._log)
        w.done.connect(self._on_artifacts_done)
        w.error.connect(self._on_error)
        w.finished.connect(lambda: self.act_artifact.setEnabled(True))
        self._keep(w)
        w.start()

    def _on_artifacts_done(self, entries: list):
        self._artifact_entries = entries
        if not entries:
            self.artifact_view.setPlainText("추출된 UserAssist 항목이 없습니다.")
            return
        lines = ["=" * 68, "  UserAssist 분석 결과", "=" * 68, ""]
        for e in entries:
            ts = e["last_run_time"].strftime("%Y-%m-%d %H:%M:%S UTC") \
                 if e["last_run_time"] else "알 수 없음"
            lines += [
                f"[{e['guid_type']}]  {e['name']}",
                f"  사용자: {e.get('username','?')}  |  실행 횟수: {e['run_count']}"
                f"  |  세션: {e['session_id']}  |  마지막 실행: {ts}",
                "",
            ]
        self.artifact_view.setPlainText("\n".join(lines))
        self.act_export.setEnabled(True)

    def _export_results(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "결과 저장", "userassist_result.txt", "Text Files (*.txt)"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.artifact_view.toPlainText())
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
        w.finished.connect(lambda: self._workers.remove(w) if w in self._workers else None)

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
                padding: 3px 8px;
            }}
            QToolBar QToolButton {{
                background: transparent;
                color: {C_TEXT};
                padding: 4px 12px;
                border-radius: 4px;
            }}
            QToolBar QToolButton:hover {{ background: {C_SELECT}; color: {C_AMBER}; }}
            QToolBar QToolButton:disabled {{ color: {C_SUBTEXT}; }}
            QLabel#panel_header {{
                background: {C_HEADER};
                color: {C_AMBER};
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
            QTreeWidget {{
                background: {C_PANEL};
                border: none;
                border-right: 1px solid {C_BORDER};
            }}
            QTreeWidget::item:selected {{ background: {C_SELECT}; color: {C_AMBER}; }}
            QTreeWidget::item:hover    {{ background: {C_SELECT}; }}
            QTableWidget {{
                background: {C_PANEL};
                border: none;
                gridline-color: {C_BORDER};
            }}
            QTableWidget::item:selected {{ background: {C_SELECT}; color: {C_AMBER}; }}
            QHeaderView::section {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                border: none;
                border-bottom: 1px solid {C_BORDER};
                padding: 4px 8px;
                font-size: 11px;
            }}
            QTabWidget#viewer_tabs::pane {{
                border: 1px solid {C_BORDER};
                background: {C_PANEL};
            }}
            QTabBar::tab {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                padding: 5px 18px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{ background: {C_PANEL}; color: {C_AMBER}; border-bottom: 2px solid {C_AMBER}; }}
            QTextEdit {{
                background: {C_PANEL};
                color: {C_GREEN};
                border: none;
            }}
            QScrollBar:vertical {{ background: {C_BG}; width: 8px; }}
            QScrollBar::handle:vertical {{ background: {C_BORDER}; border-radius: 4px; }}
            QStatusBar {{ background: {C_HEADER}; color: {C_SUBTEXT}; font-size: 11px; }}
            QSplitter::handle {{ background: {C_BORDER}; }}
        """)