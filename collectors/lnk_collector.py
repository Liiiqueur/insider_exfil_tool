from collectors.artifact_utils import extract_path_to_temp, find_files, iso_now, iter_user_directories


LNK_RELATIVE_DIRS = (
    ("Recent", "AppData/Roaming/Microsoft/Windows/Recent"),
    ("Desktop", "Desktop"),
    ("StartMenu", "AppData/Roaming/Microsoft/Windows/Start Menu"),
)


def collect_from_image(handler, fs) -> list[dict]:
    results = []
    collected_at = iso_now()
    for user in iter_user_directories(handler, fs):
        for location_name, relative_dir in LNK_RELATIVE_DIRS:
            base_dir = f"{user['path'].rstrip('/')}/{relative_dir}"
            for entry in find_files(handler, fs, base_dir, suffixes=(".lnk",), max_depth=2):
                tmp_path = extract_path_to_temp(fs, entry["path"], suffix=f"_{entry['name']}", max_bytes=8 * 1024 * 1024)
                if not tmp_path:
                    continue
                results.append({
                    "username": user["username"],
                    "source_path": entry["path"],
                    "filename": entry["name"],
                    "lnk_location": location_name,
                    "size": entry["size"],
                    "inode": entry["inode"],
                    "tmp_path": tmp_path,
                    "collected_at": collected_at,
                })
    return results
