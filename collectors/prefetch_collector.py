from __future__ import annotations

import logging
import tempfile

logger = logging.getLogger(__name__)

_PREFETCH_DIR   = "/Windows/Prefetch"
_PREFETCH_EXT   = ".pf"
_PREFETCH_MAX_BYTES = 5 * 1024 * 1024   # 5 MB


def collect_from_image(handler, fs) -> list[dict]:
    try:
        entries = handler.list_directory(fs, None, _PREFETCH_DIR)
    except Exception as e:
        logger.debug("Prefetch 디렉터리 열기 실패: %s", e)
        return []
    logger.warning("Prefetch 디렉터리 항목: %s", [e.name for e in entries])

    collected: list[dict] = []

    for entry in entries:
        if entry.is_dir or not entry.name.lower().endswith(_PREFETCH_EXT):
            continue

        result = _extract_to_temp(handler, fs, entry)
        if result is not None:
            collected.append(result)

    logger.debug("prefetch_collector: %d 개 파일 추출", len(collected))
    return collected

# ──────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────

def _extract_to_temp(handler, fs, entry) -> dict | None:
    data = handler.read_file(fs, entry.inode, max_bytes=_PREFETCH_MAX_BYTES)
    if not data:
        logger.debug("Prefetch 읽기 실패 또는 빈 파일: %s", entry.path)
        return None

    with tempfile.NamedTemporaryFile(delete=False, suffix=_PREFETCH_EXT) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    logger.debug("Prefetch 추출: %s → %s (%d bytes)", entry.path, tmp_path, len(data))

    return {
        "artifact_name": "prefetch",
        "file_name":     entry.name,
        "source_path":   entry.path,
        "temp_path":     tmp_path,
        "size":          entry.size,
        "inode":         entry.inode,
    }