import logging

from collectors.artifact_utils import WINDOWS_ROOT_CANDIDATES, extract_path_to_temp, first_existing_dir, iso_now, list_dir

logger = logging.getLogger(__name__)


def collect_from_image(handler, fs) -> list[dict]:
    results = []
    windows_root = first_existing_dir(handler, fs, WINDOWS_ROOT_CANDIDATES)
    if not windows_root:
        return results

    prefetch_dir = f"{windows_root}/Prefetch"
    entries = list_dir(handler, fs, prefetch_dir)
    collected_at = iso_now()

    for entry in entries:
        if entry.is_dir or not entry.name.lower().endswith(".pf"):
            continue

        tmp_path = extract_path_to_temp(fs, entry.path, suffix=f"_{entry.name}", max_bytes=32 * 1024 * 1024)
        if not tmp_path:
            continue

        results.append({
            "source_path": entry.path,
            "filename": entry.name,
            "size": entry.size,
            "inode": entry.inode,
            "tmp_path": tmp_path,
            "collected_at": collected_at,
        })

    logger.info("Prefetch collected: %d", len(results))
    return results
