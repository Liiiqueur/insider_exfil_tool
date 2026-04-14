import logging

from collectors.artifact_utils import WINDOWS_ROOT_CANDIDATES, extract_path_to_temp, first_existing_dir, iso_now

logger = logging.getLogger(__name__)


def collect_from_image(handler, fs) -> list[dict]:
    results = []
    windows_root = first_existing_dir(handler, fs, WINDOWS_ROOT_CANDIDATES)
    if not windows_root:
        return results

    hive_path = f"{windows_root}/System32/config/SYSTEM"
    tmp_path = extract_path_to_temp(fs, hive_path, suffix="_SYSTEM", max_bytes=256 * 1024 * 1024)
    if not tmp_path:
        return results

    results.append({
        "source_path": hive_path,
        "tmp_path": tmp_path,
        "collected_at": iso_now(),
    })
    logger.info("USB registry hive collected")
    return results
