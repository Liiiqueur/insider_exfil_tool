from __future__ import annotations

import logging
import os
import tempfile

logger = logging.getLogger(__name__)

_AMC_DIR       = "/Windows/AppCompat/Programs"
_AMC_NAME      = "amcache.hve"         # 대소문자 무시 비교
_AMC_MAX_BYTES = 50 * 1024 * 1024      # 50 MB


def collect_from_image(handler, fs) -> list[dict]:
    try:
        entries = handler.list_directory(fs, None, _AMC_DIR)
    except Exception as e:
        logger.debug("Amcache 디렉터리 열기 실패: %s", e)
        return []
    
    logger.warning("Amcache 디렉터리 항목: %s", [e.name for e in entries])

    # .hve / .LOG1 / .LOG2 를 같은 디렉터리에 보관해야 python-registry 가 자동 탐색
    tmp_dir = tempfile.mkdtemp()
    collected: list[dict] = []

    for entry in entries:
        if entry.is_dir:
            continue
        if not entry.name.lower().startswith(_AMC_NAME):
            continue

        data = handler.read_file(fs, entry.inode, max_bytes=_AMC_MAX_BYTES)
        if not data:
            logger.debug("Amcache 읽기 실패 또는 빈 파일: %s", entry.path)
            continue

        # 원본 파일명 그대로 저장 (대소문자 보존)
        dest = os.path.join(tmp_dir, entry.name)
        with open(dest, "wb") as f:
            f.write(data)
        logger.debug("Amcache 추출: %s → %s (%d bytes)", entry.path, dest, len(data))

        # .hve 본체만 결과에 추가, LOG 파일은 사이드카로만 존재
        if entry.name.lower() == _AMC_NAME:
            collected.append({
                "artifact_name": "amcache",
                "file_name":     entry.name,
                "source_path":   entry.path,
                "temp_path":     dest,
                "size":          entry.size,
                "inode":         entry.inode,
            })

    return collected