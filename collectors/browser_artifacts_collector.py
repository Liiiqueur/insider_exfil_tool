from collectors.artifact_utils import extract_path_to_temp, iso_now, iter_user_directories, list_dir


CHROMIUM_BROWSERS = (
    ("Chrome", "AppData/Local/Google/Chrome/User Data"),
    ("Edge", "AppData/Local/Microsoft/Edge/User Data"),
)
FIREFOX_ROOT = "AppData/Roaming/Mozilla/Firefox/Profiles"


def _collect_chromium(handler, fs, user: dict, browser_name: str, browser_root: str, collected_at: str, bucket: list[dict]):
    profiles_root = f"{user['path'].rstrip('/')}/{browser_root}"
    for profile in list_dir(handler, fs, profiles_root):
        if not profile.is_dir:
            continue
        profile_name = profile.name
        for artifact_name in ("History", "Cookies"):
            source_path = f"{profile.path.rstrip('/')}/{artifact_name}"
            tmp_path = extract_path_to_temp(fs, source_path, suffix=f"_{browser_name}_{profile_name}_{artifact_name}", max_bytes=256 * 1024 * 1024)
            if not tmp_path:
                continue
            bucket.append({
                "username": user["username"],
                "browser": browser_name,
                "profile": profile_name,
                "source_path": source_path,
                "source_name": artifact_name,
                "tmp_path": tmp_path,
                "collected_at": collected_at,
            })


def _collect_firefox(handler, fs, user: dict, collected_at: str, bucket: list[dict]):
    profiles_root = f"{user['path'].rstrip('/')}/{FIREFOX_ROOT}"
    for profile in list_dir(handler, fs, profiles_root):
        if not profile.is_dir:
            continue
        profile_name = profile.name
        for artifact_name in ("places.sqlite", "cookies.sqlite"):
            source_path = f"{profile.path.rstrip('/')}/{artifact_name}"
            tmp_path = extract_path_to_temp(fs, source_path, suffix=f"_Firefox_{profile_name}_{artifact_name}", max_bytes=256 * 1024 * 1024)
            if not tmp_path:
                continue
            bucket.append({
                "username": user["username"],
                "browser": "Firefox",
                "profile": profile_name,
                "source_path": source_path,
                "source_name": artifact_name,
                "tmp_path": tmp_path,
                "collected_at": collected_at,
            })


def collect_from_image(handler, fs) -> list[dict]:
    results = []
    collected_at = iso_now()
    for user in iter_user_directories(handler, fs):
        for browser_name, browser_root in CHROMIUM_BROWSERS:
            _collect_chromium(handler, fs, user, browser_name, browser_root, collected_at, results)
        _collect_firefox(handler, fs, user, collected_at, results)
    return results
