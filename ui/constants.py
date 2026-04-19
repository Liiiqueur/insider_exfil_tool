import os
import sys
import tempfile

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
    usb_collector,
    spool_collector,
    prefetch_collector,
    amcache_collector,
    ost_pst_collector,
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
    usb_parser,
    spool_parser,
    prefetch_parser,
    amcache_parser,
    ost_pst_parser,
)
from parsers.artifact_weights import attach_artifact_weight

# ──────────────────────────────────────────
# 색상 팔레트
# ──────────────────────────────────────────
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

# ──────────────────────────────────────────
# 아티팩트 레지스트리
# ──────────────────────────────────────────
ARTIFACT_REGISTRY = [
    {"id": "filesystem",       "label": "$MFT, $J",         "description": "NTFS metadata reconstructed from $MFT plus raw $J collection",                                                                  "color": C_AMBER},
    {"id": "lnk",             "label": "LNK",              "description": "Shortcut files from Recent, Desktop, and Start Menu",                                                                              "color": C_PURPLE},
    {"id": "eventlog",        "label": "Event Log",        "description": "Security and device event logs related to file access, process creation, logon, and USB activity",                                "color": C_RED},
    {"id": "recentdocs",      "label": "RecentDocs",       "description": "RecentDocs registry traces from NTUSER.DAT",                                                                                     "color": C_BLUE},
    {"id": "browser_artifacts","label": "Browser History",  "description": "Browser history, downloads, and cookies from Chrome, Edge, and Firefox",                                                         "color": C_GREEN},
    {"id": "userassist",      "label": "UserAssist",       "description": "NTUSER.DAT UserAssist execution evidence",                                                                                        "color": C_BLUE},
    {"id": "jumplist",        "label": "Jumplist",         "description": "Recent file and application history",                                                                                             "color": C_PURPLE},
    {"id": "shellbags",       "label": "Shellbags",        "description": "Explorer folder access traces",                                                                                                   "color": C_BLUE},
    {"id": "mounteddevices",  "label": "MountedDevices",   "description": "Drive letter and volume mapping data",                                                                                           "color": C_PURPLE},
    {"id": "usb",             "label": "USB Devices",      "description": "USB device connection and usage traces from registry and system logs",                                                            "color": C_AMBER},
    {"id": "spool",           "label": "Print Spool",      "description": "Printer spool files (.SPL/.SHD) including print jobs",                                                                           "color": C_RED},
    {"id": "prefetch",        "label": "Prefetch",         "description": "Program execution traces from Windows Prefetch files",                                                                            "color": C_GREEN},
    {"id": "amcache",         "label": "Amcache",          "description": "Application metadata and execution traces from Amcache.hve",                                                                     "color": C_GREEN},
    {"id": "ost_pst",         "label": "OST/PST (Outlook)","description": "Extracts Outlook PST/OST metadata, including deleted items",                                                                     "color": C_BLUE},
]

# id → 메타 딕셔너리 빠른 조회용
ARTIFACT_INDEX: dict = {item["id"]: item for item in ARTIFACT_REGISTRY}


# ──────────────────────────────────────────
# 러너 헬퍼 함수
# ──────────────────────────────────────────

def _cleanup_entries(entries: list[dict]) -> None:
    cleanup_temp_paths(entries)


def _run_userassist(handler: ImageHandler, log_cb) -> list[dict]:
    all_entries: list[dict] = []
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
                raw    = userassist_collector.collect(tmp_path)
                parsed = userassist_parser.parse(raw)
                all_entries.extend(
                    attach_artifact_weight(entry, "userassist") for entry in parsed
                )
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
    return all_entries


def _run_jumplist(handler: ImageHandler, log_cb) -> list[dict]:
    collected: list[dict] = []
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
    collected: list[dict] = []
    for vol in handler.volumes:
        fs = vol["fs"]
        log_cb(f"[INFO] [{vol['desc']}] collecting {collector_module.__name__.split('.')[-1]}")
        collected.extend(collector_module.collect_from_image(handler, fs))
    try:
        return parser_module.parse(collected)
    finally:
        _cleanup_entries(collected)


# ──────────────────────────────────────────
# 아티팩트 ID → 러너 함수 매핑
# ──────────────────────────────────────────
ARTIFACT_RUNNERS: dict = {
    "filesystem":       lambda h, cb: _run_module(h, cb, filesystem_collector,        filesystem_parser),
    "lnk":             lambda h, cb: _run_module(h, cb, lnk_collector,               lnk_parser),
    "eventlog":        lambda h, cb: _run_module(h, cb, eventlog_collector,           eventlog_parser),
    "recentdocs":      lambda h, cb: _run_module(h, cb, recentdocs_collector,         recentdocs_parser),
    "browser_artifacts":lambda h, cb: _run_module(h, cb, browser_artifacts_collector, browser_artifacts_parser),
    "userassist":      lambda h, cb: _run_userassist(h, cb),
    "jumplist":        lambda h, cb: _run_jumplist(h, cb),
    "shellbags":       lambda h, cb: _run_module(h, cb, shellbags_collector,          shellbags_parser),
    "mounteddevices":  lambda h, cb: _run_module(h, cb, mounteddevices_collector,     mounteddevices_parser),
    "usb":             lambda h, cb: _run_module(h, cb, usb_collector,               usb_parser),
    "spool":           lambda h, cb: _run_module(h, cb, spool_collector,             spool_parser),
    "prefetch":        lambda h, cb: _run_module(h, cb, prefetch_collector,          prefetch_parser),
    "amcache":         lambda h, cb: _run_module(h, cb, amcache_collector,           amcache_parser),
    "ost_pst":         lambda h, cb: _run_module(h, cb, ost_pst_collector,           ost_pst_parser),
}