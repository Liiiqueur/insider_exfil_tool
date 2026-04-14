import os
import tempfile
from datetime import datetime, timezone
from typing import Optional, Tuple


USER_ROOT_CANDIDATES = (
    "/Users",
    "/C:/Users",
    "Users",
)

WINDOWS_ROOT_CANDIDATES = (
    "/Windows",
    "/C:/Windows",
    "Windows",
)

SKIP_USERS = {"default", "default user", "public", "all users"}


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_tsk_path(path: str) -> str:
    if not path:
        return "/"
    fixed = path.replace("\\", "/")
    if not fixed.startswith("/"):
        fixed = "/" + fixed
    return fixed


def list_dir(handler, fs, path: str) -> list:
    try:
        return handler.list_directory(fs, inode=None, path=normalize_tsk_path(path))
    except Exception:
        return []


def first_existing_dir(handler, fs, candidates: Tuple[str, ...]) -> Optional[str]:
    for candidate in candidates:
        if list_dir(handler, fs, candidate):
            return normalize_tsk_path(candidate)
    return None


def iter_user_directories(handler, fs) -> list[dict]:
    users_root = first_existing_dir(handler, fs, USER_ROOT_CANDIDATES)
    if not users_root:
        return []

    results = []
    for entry in list_dir(handler, fs, users_root):
        if not entry.is_dir:
            continue
        if entry.name.lower() in SKIP_USERS:
            continue
        results.append({
            "username": entry.name,
            "path": entry.path,
            "inode": entry.inode,
        })
    return results


def read_file_by_path(fs, path: str, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    try:
        file_obj = fs.open(path=normalize_tsk_path(path))
        size = min(file_obj.info.meta.size, max_bytes)
        return file_obj.read_random(0, size)
    except Exception:
        return b""


def extract_path_to_temp(fs, path: str, suffix: str = "", max_bytes: int = 64 * 1024 * 1024) -> Optional[str]:
    raw = read_file_by_path(fs, path, max_bytes=max_bytes)
    if not raw:
        return None

    fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return None
    return tmp_path


def find_files(handler, fs, root_path: str, suffixes: Optional[Tuple[str, ...]] = None, names: Optional[Tuple[str, ...]] = None, max_depth: int = 4) -> list[dict]:
    suffixes = tuple(s.lower() for s in (suffixes or ()))
    exact_names = {name.lower() for name in (names or ())}
    root_path = normalize_tsk_path(root_path)
    results: list[dict] = []

    def walk(path: str, depth: int) -> None:
        if depth > max_depth:
            return
        for entry in list_dir(handler, fs, path):
            if entry.is_dir:
                walk(entry.path, depth + 1)
                continue

            lower_name = entry.name.lower()
            if suffixes and lower_name.endswith(suffixes):
                results.append({
                    "name": entry.name,
                    "path": entry.path,
                    "inode": entry.inode,
                    "size": entry.size,
                })
                continue

            if exact_names and lower_name in exact_names:
                results.append({
                    "name": entry.name,
                    "path": entry.path,
                    "inode": entry.inode,
                    "size": entry.size,
                })

    walk(root_path, 0)
    return results


def cleanup_temp_paths(entries: list[dict], key: str = "tmp_path") -> None:
    for entry in entries:
        tmp_path = entry.get(key)
        if not tmp_path:
            continue
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
