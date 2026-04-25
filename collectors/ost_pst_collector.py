from __future__ import annotations

import logging
import os
import struct

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 상수
# ──────────────────────────────────────────

_PFF_MAGIC = b"\x21\x42\x44\x4E"   # "!BDN"

_MAGIC_CLIENT_MAP: dict[int, str] = {
    0x4D50: "PST",
    0x4D4F: "OST",
    0x4D53: "PAB",
}

_FORMAT_VER_MAP: dict[int, str] = {
    14: "ANSI/32-bit",      # Outlook 97-2002
    23: "Unicode/64-bit",   # Outlook 2003+
    36: "Unicode/4K-page",  # Outlook 2013+ 압축 OST
}

# 사용자 홈 루트 (볼륨 절대 경로)
_USER_HOME_ROOTS = ("/Users", "/Documents and Settings")

# 사용자 홈 기준 상대 탐색 경로
_PROFILE_RELATIVE_DIRS = (
    "AppData/Local/Microsoft/Outlook",
    "AppData/Roaming/Microsoft/Outlook",
    "Documents/Outlook Files",
    "Documents",
    "Desktop",
    "OneDrive/Documents/Outlook Files",
    "OneDrive - Personal/Documents/Outlook Files",
)

# 무시할 시스템/기본 사용자 폴더
_SKIP_USERNAMES = frozenset(
    {".", "..", "Public", "Default", "Default User", "All Users"}
)

try:
    import pytsk3 as _pytsk3
    _TSK_META_DIR = _pytsk3.TSK_FS_META_TYPE_DIR
except Exception:
    _TSK_META_DIR = 2   # fallback

# ══════════════════════════════════════════
# pytsk3 스트리밍 파일 객체
# ══════════════════════════════════════════

class _TskFileObject:

    def __init__(self, tsk_file):
        self._file   = tsk_file
        meta         = tsk_file.info.meta
        self._size   = int(meta.size) if meta and meta.size else 0
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if self._offset >= self._size:
            return b""
        if size < 0:
            size = self._size - self._offset
        to_read = min(size, self._size - self._offset)
        if to_read == 0:
            return b""
        try:
            data = self._file.read_random(self._offset, to_read)
        except Exception as exc:
            logger.debug("_TskFileObject.read 오류 (offset=%d): %s", self._offset, exc)
            return b""
        self._offset += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        if   whence == 0: self._offset  = offset
        elif whence == 1: self._offset += offset
        elif whence == 2: self._offset  = self._size + offset
        self._offset = max(0, min(self._offset, self._size))
        return self._offset

    def tell(self) -> int:      return self._offset
    def get_size(self) -> int:  return self._size
    def readable(self) -> bool: return True
    def seekable(self) -> bool: return True
    def writable(self) -> bool: return False


# ══════════════════════════════════════════
# 공개 API
# ══════════════════════════════════════════

def collect_from_image(handler, fs) -> list[dict]:
    results: list[dict] = []
    users = _enumerate_users(fs)

    if not users:
        logger.warning("OST/PST: 이 볼륨에 사용자 홈 디렉터리 없음")
        return results

    for user in users:
        for rel_dir in _PROFILE_RELATIVE_DIRS:
            for path_variant in _path_variants(user["home_path"], rel_dir):
                _scan_directory(fs, path_variant, user["username"], results)

    if not results:
        logger.debug("OST/PST: PST/OST 파일 없음 (user=%s)", [u["username"] for u in users])

    logger.info("OST/PST: %d 개 파일 발견", len(results))
    return results


def collect(file_path: str) -> list[dict]:
    if not os.path.isfile(file_path):
        return []

    with open(file_path, "rb") as f:
        header_data = f.read(16)

    header = _parse_pff_header(header_data)
    if not header["is_pff"]:
        logger.warning("PFF 매직 불일치: %s", file_path)
        return []

    return [_build_entry(
        source_path  = file_path,
        header       = header,
        file_size    = os.path.getsize(file_path),
        username     = "",
        file_object  = None,
        local_path   = file_path,
    )]


# ══════════════════════════════════════════
# 내부 — 이미지 탐색
# ══════════════════════════════════════════

def _enumerate_users(fs) -> list[dict]:
    users: list[dict] = []
    for root in _USER_HOME_ROOTS:
        d = _try_open_dir(fs, root)
        if d is None:
            continue
        for entry in _iter_dir_entries(d):
            name = _decode_name(entry)
            if name in _SKIP_USERNAMES:
                continue
            meta = entry.info.meta
            if meta is None:
                continue
            # meta.type 하드코딩 대신 pytsk3 상수와 비교
            # 타입 불일치 방어: 디렉터리이거나 타입 판별 불가 시 포함
            is_dir = (meta.type == _TSK_META_DIR)
            logger.warning("  meta.type=%s, _TSK_META_DIR=%s, match=%s",
               meta.type if meta else None, _TSK_META_DIR,
               meta.type == _TSK_META_DIR if meta else False)
            if not is_dir:
                continue
            users.append({
                "username":  name,
                "home_path": f"{root}/{name}",
            })
            
    return users

def _debug_list_home(fs, home_path: str):
    """홈 디렉터리 1단계 전체 목록 출력 (진단용)"""
    d = _try_open_dir(fs, home_path)
    if d is None:
        logger.warning("홈 디렉터리 열기 실패: %s", home_path)
        return
    for entry in _iter_dir_entries(d):
        name = _decode_name(entry)
        meta = entry.info.meta
        meta_type = meta.type if meta else "None"
        logger.warning("  [%s] %s/%s", meta_type, home_path, name)


def _scan_directory(
    fs,
    dir_path: str,
    username: str,
    results: list[dict],
    depth: int = 0,
) -> None:
    d = _try_open_dir(fs, dir_path)
    logger.warning("PST/OST 탐색: '%s' → %s", dir_path, "성공" if d else "실패")
    if d is None:
        return

    try:
        for entry in _iter_dir_entries(d):
            name      = _decode_name(entry)
            full_path = f"{dir_path}/{name}".replace("//", "/")
            meta      = entry.info.meta
            if meta is None:
                continue

            if meta.type == _TSK_META_DIR:
                if depth == 0:
                    _scan_directory(fs, full_path, username, results, depth=1)
                continue

            if not name.lower().endswith((".pst", ".ost")):
                continue

            record = _collect_pff_file(fs, full_path, meta, username)
            if record is not None:
                results.append(record)

    except Exception as exc:
        logger.debug("디렉터리 스캔 오류 [%s]: %s", dir_path, exc)


def _collect_pff_file(fs, full_path: str, meta, username: str) -> dict | None:
    try:
        f           = fs.open(full_path)
        header_data = f.read_random(0, 16)
    except Exception:
        return None

    header = _parse_pff_header(header_data)
    if not header["is_pff"]:
        logger.debug("PST/OST 매직 불일치: %s", full_path)
        return None

    file_size = int(meta.size) if meta.size else 0
    logger.debug(
        "발견: %s [%s %s] %.1f MB user=%s",
        full_path, header["file_type"], header["format"],
        file_size / (1024 * 1024), username,
    )
    return _build_entry(
        source_path = full_path,
        header      = header,
        file_size   = file_size,
        username    = username,
        file_object = _TskFileObject(f),
    )


# ══════════════════════════════════════════
# 내부 — 항목 조립
# ══════════════════════════════════════════

def _build_entry(
    source_path: str,
    header: dict,
    file_size: int,
    username: str,
    file_object,
    local_path: str | None = None,
) -> dict:
    return {
        "source_path":  source_path,
        "file_type":    header["file_type"],
        "format":       header["format"],
        "format_ver":   header["format_ver"],
        "file_size":    file_size,
        "username":     username,
        "file_object":  file_object,
        "_local_path":  local_path,
        "_temp_path":   None,
    }


# ══════════════════════════════════════════
# 내부 — PFF 헤더 파싱
# ══════════════════════════════════════════

def _parse_pff_header(data: bytes) -> dict:
    result = {"is_pff": False, "file_type": "Unknown", "format": "Unknown", "format_ver": 0}
    if not data or len(data) < 12:
        return result
    if data[:4] != _PFF_MAGIC:
        return result

    magic_client = struct.unpack_from("<H", data, 6)[0]
    w_ver        = struct.unpack_from("<H", data, 8)[0]
    result.update({
        "is_pff":      True,
        "file_type":   _MAGIC_CLIENT_MAP.get(magic_client, "Unknown"),
        "format_ver":  w_ver,
        "format":      _FORMAT_VER_MAP.get(w_ver, f"Unknown(v{w_ver})"),
    })
    return result


# ══════════════════════════════════════════
# 내부 — pytsk3 유틸
# ══════════════════════════════════════════

def _try_open_dir(fs, path: str):
    try:
        return fs.open_dir(path)
    except Exception:
        return None


def _iter_dir_entries(directory):
    try:
        for entry in directory:
            name = _decode_name(entry)
            if name not in (".", ".."):
                yield entry
    except Exception:
        return


def _decode_name(entry) -> str:
    name = entry.info.name.name
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="replace")
    return name or ""


# ══════════════════════════════════════════
# 내부 — 경로 유틸
# ══════════════════════════════════════════

def _path_variants(home_path: str, rel_dir: str) -> list[str]:
    base     = f"{home_path}/{rel_dir}"
    lowered  = f"{home_path}/{rel_dir.lower()}"
    variants = {base, lowered}
    return list(variants)