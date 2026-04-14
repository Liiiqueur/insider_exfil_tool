import os
import logging

from collectors.artifact_utils import WINDOWS_ROOT_CANDIDATES, extract_path_to_temp, first_existing_dir, iso_now, list_dir

logger = logging.getLogger(__name__)


def collect_from_image(handler, fs) -> list[dict]:
    results = []
    windows_root = first_existing_dir(handler, fs, WINDOWS_ROOT_CANDIDATES)
    if not windows_root:
        return results

    spool_dir = f"{windows_root}/System32/spool/PRINTERS"
    entries = list_dir(handler, fs, spool_dir)
    collected_at = iso_now()

    for entry in entries:
        if entry.is_dir:
            continue

        lower_name = entry.name.lower()
        if not lower_name.endswith((".spl", ".shd")):
            continue

        tmp_path = extract_path_to_temp(fs, entry.path, suffix=f"_{entry.name}", max_bytes=128 * 1024 * 1024)
        if not tmp_path:
            continue

        results.append({
            "filename": entry.name,
            "job_id": os.path.splitext(entry.name)[0],
            "extension": os.path.splitext(entry.name)[1].lower(),
            "source_path": entry.path,
            "size": entry.size,
            "inode": entry.inode,
            "tmp_path": tmp_path,
            "collected_at": collected_at,
        })

    logger.info("Printer spool files collected: %d", len(results))
    return results
