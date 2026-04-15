import os

from collectors.artifact_utils import extract_path_to_temp, iso_now, iter_user_directories


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
            "hive_name": os.path.basename(hive_path),
            "tmp_path": tmp_path,
            "collected_at": collected_at,
        })
    return results
