import logging

from collectors.artifact_utils import WINDOWS_ROOT_CANDIDATES, extract_path_to_temp, first_existing_dir, iso_now

logger = logging.getLogger(__name__)


AMC_PATHS = (
    "AppCompat/Programs/Amcache.hve",
    "appcompat/Programs/Amcache.hve",
)


def collect_from_image(handler, fs) -> list[dict]:
    results = []
    windows_root = first_existing_dir(handler, fs, WINDOWS_ROOT_CANDIDATES)
    if not windows_root:
        return results

    collected_at = iso_now()
    for relative_path in AMC_PATHS:
        hive_path = f"{windows_root}/{relative_path}"
        tmp_path = extract_path_to_temp(fs, hive_path, suffix="_Amcache.hve", max_bytes=256 * 1024 * 1024)
        if not tmp_path:
            continue

        results.append({
            "source_path": hive_path,
            "tmp_path": tmp_path,
            "collected_at": collected_at,
        })
        break

    logger.info("Amcache hives collected: %d", len(results))
    return results
