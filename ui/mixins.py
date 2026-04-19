import json
import logging
import os

from PyQt5.QtGui import QFont

from .constants import (
    C_BG, C_PANEL, C_BORDER, C_HEADER, C_TEXT,
    C_SUBTEXT, C_SELECT, C_BLUE,
)

logger = logging.getLogger(__name__)

SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "..", ".ui_settings.json")


# ══════════════════════════════════════════
# SettingsMixin
# ══════════════════════════════════════════

class SettingsMixin:

    # ── 저수준 JSON I/O ──────────────────────

    def _load_settings(self) -> dict:
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_settings(self, data: dict) -> None:
        try:
            with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.debug("failed to save ui settings: %s", exc)

    # ── 폰트 스케일 ──────────────────────────

    def _load_font_scale_percent(self) -> int:
        try:
            data  = self._load_settings()
            value = int(data.get("font_scale_percent", 100))
            return max(50, min(200, value))
        except Exception:
            return 100

    def _save_font_scale_percent(self) -> None:
        data = self._load_settings()
        data["font_scale_percent"] = self._font_scale_percent
        self._save_settings(data)

    def _change_font_scale(self, delta: int) -> None:
        value = max(50, min(200, self._font_scale_percent + delta))
        self._set_font_scale_percent(value)

    def _set_font_scale_percent(self, value: int) -> None:
        self._font_scale_percent = value
        self._save_font_scale_percent()
        self._apply_dynamic_fonts()   # StyleMixin에서 제공
        self._apply_style()           # StyleMixin에서 제공

    # ── 최근 이미지 ──────────────────────────

    def _load_recent_images(self) -> list[str]:
        data  = self._load_settings()
        items = data.get("recent_images", [])
        if not isinstance(items, list):
            return []
        return [
            path for path in items
            if isinstance(path, str) and os.path.exists(path)
        ][:3]

    def _remember_recent_image(self, path: str) -> None:
        data  = self._load_settings()
        items = data.get("recent_images", [])
        if not isinstance(items, list):
            items = []
        normalized = os.path.abspath(path)
        items = [
            item for item in items
            if isinstance(item, str)
            and os.path.exists(item)
            and os.path.abspath(item) != normalized
        ]
        items.insert(0, normalized)
        data["recent_images"] = items[:3]
        self._save_settings(data)


# ══════════════════════════════════════════
# StyleMixin
# ══════════════════════════════════════════

class StyleMixin:

    def _scaled_pt(self, base_pt: int) -> int:
        return max(int(round(base_pt * self._font_scale_percent / 100)), 1)

    def _apply_dynamic_fonts(self) -> None:
        mono = "Consolas"
        self.log_output.setFont(QFont(mono, self._scaled_pt(9)))
        self.hex_view.setFont(QFont(mono, self._scaled_pt(10)))
        self.text_view.setFont(QFont(mono, self._scaled_pt(10)))
        self.meta_view.setFont(QFont(mono, self._scaled_pt(10)))
        self.result_overview.setFont(QFont(mono, self._scaled_pt(10)))
        self.result_raw.setFont(QFont(mono, self._scaled_pt(9)))
        self.result_parsed_table.setFont(QFont(mono, self._scaled_pt(9)))

        prop = "Malgun Gothic"
        base = self._base_font_pt
        for i in range(self.artifact_list.count()):
            self.artifact_list.item(i).setFont(QFont(prop, self._scaled_pt(base)))

        self.font_scale_label.setText(f"{self._font_scale_percent}%")
        self.font_down_btn.setEnabled(self._font_scale_percent > 50)
        self.font_up_btn.setEnabled(self._font_scale_percent < 200)

    def _apply_style(self) -> None:
        base = self._base_font_pt
        s    = self._scaled_pt

        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {C_BG};
                color: {C_TEXT};
                font-family: 'Malgun Gothic', 'Segoe UI', sans-serif;
                font-size: {s(base)}pt;
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
                font-size: {s(base)}pt;
            }}
            QToolBar QToolButton:hover {{
                background: {C_SELECT};
                color: {C_BLUE};
            }}
            QLabel#panel_header {{
                background: {C_HEADER};
                color: {C_BLUE};
                font-weight: bold;
                font-size: {max(s(base - 1), 8)}pt;
                padding-left: 8px;
                border-bottom: 1px solid {C_BORDER};
            }}
            QLabel#log_header {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                font-size: {max(s(base - 2), 8)}pt;
                padding-left: 8px;
            }}
            QLabel#art_title {{
                font-weight: bold;
                font-size: {s(base)}pt;
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
            QTreeWidget::item:selected,
            QListWidget::item:selected,
            QTableWidget::item:selected {{
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
                border-right:  1px solid {C_BORDER};
                padding: 4px 8px;
                font-size: {max(s(base - 1), 8)}pt;
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
                font-size: {max(s(base - 1), 8)}pt;
            }}
            QPushButton#run_btn:hover    {{ background: #1d4ed8; }}
            QPushButton#run_btn:disabled {{ background: {C_SUBTEXT}; }}
            QPushButton#font_scale_btn {{
                background: transparent;
                color: {C_TEXT};
                border: none;
                padding: 0 2px;
                min-width: 20px;
            }}
            QPushButton#font_scale_btn:hover   {{ color: {C_BLUE}; }}
            QPushButton#font_scale_btn:pressed  {{ color: #1d4ed8; }}
            QPushButton#font_scale_btn:disabled {{ color: {C_SUBTEXT}; }}
            QTabWidget#viewer_tabs::pane,
            QTabWidget#result_tabs::pane {{
                border: 1px solid {C_BORDER};
                background: {C_PANEL};
            }}
            QTabBar::tab {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                padding: 5px 16px;
                border-top-left-radius:  4px;
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
                selection-color: {C_BLUE};
            }}
            QStatusBar {{
                background: {C_HEADER};
                color: {C_SUBTEXT};
                font-size: {max(s(base - 1), 8)}pt;
            }}
            QSplitter::handle {{
                background: {C_BORDER};
                width: 1px;
                height: 1px;
            }}
        """)