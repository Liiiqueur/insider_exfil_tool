from __future__ import annotations

import logging
import tempfile

logger = logging.getLogger(__name__)

_SPOOL_DIR      = "/Windows/System32/spool/PRINTERS"
_SPOOL_EXTS     = frozenset({".spl", ".shd"})
_SPOOL_MAX_BYTES = 10 * 1024 * 1024     # 10 MB


def collect_from_image(handler, fs) -> list[dict]:
    try:
        entries = handler.list_directory(fs, None, _SPOOL_DIR)
    except Exception as e:
        logger.debug("스풀 디렉터리 열기 실패: %s", e)
        return []

    collected: list[dict] = []

    for entry in entries:
        if entry.is_dir:
            continue
        if not _is_spool_file(entry.name):
            continue

        result = _extract_to_temp(handler, fs, entry)
        if result is not None:
            collected.append(result)

    logger.debug("spool_collector: %d 개 파일 추출", len(collected))
    return collected


# ──────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────

def _is_spool_file(name: str) -> bool:
    return any(name.lower().endswith(ext) for ext in _SPOOL_EXTS)


def _file_type(name: str) -> str:
    return "SHD" if name.lower().endswith(".shd") else "SPL"


def _extract_to_temp(handler, fs, entry) -> dict | None:
    data = handler.read_file(fs, entry.inode, max_bytes=_SPOOL_MAX_BYTES)
    if not data:
        logger.debug("스풀 파일 읽기 실패 또는 빈 파일: %s", entry.path)
        return None

    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{entry.name}") as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    logger.debug("스풀 추출: %s → %s (%d bytes)", entry.path, tmp_path, len(data))

    return {
        "artifact_name": "spool",
        "file_type":     _file_type(entry.name),
        "file_name":     entry.name,
        "source_path":   entry.path,
        "temp_path":     tmp_path,
        "size":          entry.size,
        "inode":         entry.inode,
    }