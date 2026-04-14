import logging

from collectors.artifact_utils import extract_path_to_temp, find_files, iso_now, iter_user_directories

logger = logging.getLogger(__name__)


OUTLOOK_RELATIVE_DIRS = (
    "AppData/Local/Microsoft/Outlook",
    "Documents/Outlook Files",
    "OneDrive/Documents/Outlook Files",
)


def collect_from_image(handler, fs) -> list[dict]:
    results = []
    collected_at = iso_now()

    for user in iter_user_directories(handler, fs):
        for relative_dir in OUTLOOK_RELATIVE_DIRS:
            base_dir = f"{user['path'].rstrip('/')}/{relative_dir}"
            for entry in find_files(handler, fs, base_dir, suffixes=(".ost", ".pst"), max_depth=1):
                tmp_path = extract_path_to_temp(fs, entry["path"], suffix=f"_{entry['name']}", max_bytes=256 * 1024 * 1024)
                if not tmp_path:
                    continue

                results.append({
                    "username": user["username"],
                    "store_type": entry["name"].rsplit(".", 1)[-1].upper(),
                    "filename": entry["name"],
                    "source_path": entry["path"],
                    "size": entry["size"],
                    "inode": entry["inode"],
                    "tmp_path": tmp_path,
                    "collected_at": collected_at,
                })

    logger.info("Outlook stores collected: %d", len(results))
    return results
