import logging

from collectors.artifact_utils import extract_path_to_temp, iso_now, iter_user_directories

logger = logging.getLogger(__name__)


def collect_from_image(handler, fs) -> list[dict]:
    results = []
    collected_at = iso_now()

    for user in iter_user_directories(handler, fs):
        hive_path = f"{user['path'].rstrip('/')}/NTUSER.DAT"
        tmp_path = extract_path_to_temp(fs, hive_path, suffix=f"_{user['username']}_NTUSER.DAT", max_bytes=128 * 1024 * 1024)
        if not tmp_path:
            continue

        results.append({
            "username": user["username"],
            "source_path": hive_path,
            "tmp_path": tmp_path,
            "collected_at": collected_at,
        })

    logger.info("Shellbags hives collected: %d", len(results))
    return results
