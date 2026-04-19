import logging
import os
import struct

logger = logging.getLogger(__name__)

# ─── 상수 ──────────────────────────────────────────────────────────────────────

_PFF_MAGIC = b"\x21\x42\x44\x4E"  # "!BDN"

# wMagicClient 값 → 파일 종류 문자열
_MAGIC_CLIENT_MAP = {
    0x4D50: "PST",
    0x4D4F: "OST",
    0x4D53: "PAB",
}

# wVer 값 → 포맷 설명 문자열
_FORMAT_VER_MAP = {
    14: "ANSI/32-bit",     # Outlook 97-2002
    23: "Unicode/64-bit",  # Outlook 2003+
    36: "Unicode/4K-page", # Outlook 2013+ 압축 OST
}

# 검색할 디렉토리 경로 목록 (pytsk3 경로 표기, 소문자로도 시도)
# 사용자 프로파일 루트와 조합해서 사용
_PROFILE_RELATIVE_DIRS = [
    "AppData/Local/Microsoft/Outlook",
    "AppData/Roaming/Microsoft/Outlook",
    "Documents/Outlook Files",
    "Documents",
    "Desktop",
    "OneDrive/Documents/Outlook Files",
    "OneDrive - Personal/Documents/Outlook Files",
]

# 탐색할 볼륨 내 사용자 홈 루트
_USER_HOME_ROOTS = [
    "Users",
    "Documents and Settings",  # XP 레거시
]


# ─── pytsk3 스트리밍 파일 오브젝트 ─────────────────────────────────────────────

class _TskFileObject:
    def __init__(self, tsk_file):
        self._file = tsk_file
        meta = tsk_file.info.meta
        self._size = int(meta.size) if meta and meta.size else 0
        self._offset = 0

    # ── 기본 I/O ────────────────────────────────────────────────────────────────

    def read(self, size: int = -1) -> bytes:
        if self._offset >= self._size:
            return b""
        if size < 0:
            size = self._size - self._offset
        size = min(size, self._size - self._offset)
        if size == 0:
            return b""
        try:
            data = self._file.read_random(self._offset, size)
        except Exception as exc:
            logger.debug("_TskFileObject.read error at offset %d: %s", self._offset, exc)
            return b""
        self._offset += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._offset = offset
        elif whence == 1:
            self._offset += offset
        elif whence == 2:
            self._offset = self._size + offset
        self._offset = max(0, min(self._offset, self._size))
        return self._offset

    def tell(self) -> int:
        return self._offset

    def get_size(self) -> int:
        return self._size

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False


# ─── PFF 헤더 파싱 ─────────────────────────────────────────────────────────────

def _parse_pff_header(data: bytes) -> dict:
    result = {"is_pff": False, "file_type": "Unknown", "format": "Unknown", "format_ver": 0}
    if not data or len(data) < 12:
        return result
    if data[:4] != _PFF_MAGIC:
        return result
    result["is_pff"] = True
    magic_client = struct.unpack_from("<H", data, 6)[0]
    w_ver = struct.unpack_from("<H", data, 8)[0]
    result["file_type"] = _MAGIC_CLIENT_MAP.get(magic_client, "Unknown")
    result["format_ver"] = w_ver
    result["format"] = _FORMAT_VER_MAP.get(w_ver, f"Unknown(v{w_ver})")
    return result


# ─── 이미지 내 파일 탐색 ────────────────────────────────────────────────────────

def _try_open(fs, path: str):
    try:
        return fs.open(path)
    except Exception:
        return None


def _try_dir(fs, path: str):
    try:
        return fs.open_dir(path)
    except Exception:
        return None


def _scan_dir_for_pst_ost(fs, dir_path: str, username: str, results: list, depth: int = 0):
    d = _try_dir(fs, dir_path)
    if d is None:
        return
    try:
        for entry in d:
            name = entry.info.name.name
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            if name in (".", ".."):
                continue
            full_path = f"{dir_path}/{name}".replace("//", "/")
            meta = entry.info.meta
            if meta is None:
                continue
            is_dir = (meta.type == 2)  # TSK_FS_META_TYPE_DIR = 2
            lower_name = name.lower()
            if is_dir and depth == 0:
                # 서브 디렉토리 1단계 더 탐색 (예: Outlook 프로파일 폴더)
                _scan_dir_for_pst_ost(fs, full_path, username, results, depth=1)
                continue
            if not lower_name.endswith(".pst") and not lower_name.endswith(".ost"):
                continue
            # 첫 16바이트로 PFF 헤더 확인
            try:
                f = fs.open(full_path)
                header_data = f.read_random(0, 16)
            except Exception:
                continue
            header = _parse_pff_header(header_data)
            if not header["is_pff"]:
                logger.debug("PST/OST 매직 불일치: %s", full_path)
                continue
            file_size = int(meta.size) if meta.size else 0
            file_obj = _TskFileObject(f)
            results.append({
                "source_path": full_path,
                "file_type": header["file_type"],
                "format": header["format"],
                "format_ver": header["format_ver"],
                "file_size": file_size,
                "username": username,
                "file_object": file_obj,
                # 정리 대상 없음 (temp 파일 없이 스트리밍)
                "_temp_path": None,
            })
            logger.debug(
                "발견: %s [%s %s] %.1f MB user=%s",
                full_path,
                header["file_type"],
                header["format"],
                file_size / (1024 * 1024),
                username,
            )
    except Exception as exc:
        logger.debug("디렉토리 스캔 오류 [%s]: %s", dir_path, exc)


def _enumerate_users(fs) -> list:
    users = []
    for root in _USER_HOME_ROOTS:
        d = _try_dir(fs, f"/{root}")
        if d is None:
            continue
        try:
            for entry in d:
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                if name in (".", "..", "Public", "Default", "Default User", "All Users"):
                    continue
                meta = entry.info.meta
                if meta is None:
                    continue
                if meta.type == 2:  # 디렉토리
                    users.append({
                        "username": name,
                        "home_path": f"/{root}/{name}",
                    })
        except Exception:
            pass
    return users


# ─── 공개 인터페이스 ───────────────────────────────────────────────────────────

def collect_from_image(handler, fs) -> list:
    results = []
    users = _enumerate_users(fs)
    if not users:
        logger.warning("OST/PST: 사용자 홈 디렉토리를 찾을 수 없습니다.")
        return results

    for user in users:
        home = user["home_path"]
        username = user["username"]
        for rel_dir in _PROFILE_RELATIVE_DIRS:
            # Windows는 대소문자 구분 없음, 소문자/대소문자 혼합 모두 시도
            for cased_dir in _path_variants(rel_dir):
                target = f"{home}/{cased_dir}"
                _scan_dir_for_pst_ost(fs, target, username, results)

    logger.info("OST/PST: %d개 파일 발견", len(results))
    return results


def collect(file_path: str) -> list:
    results = []
    if not os.path.isfile(file_path):
        return results
    with open(file_path, "rb") as f:
        header_data = f.read(16)
    header = _parse_pff_header(header_data)
    if not header["is_pff"]:
        logger.warning("PFF 매직 불일치: %s", file_path)
        return results
    file_size = os.path.getsize(file_path)
    results.append({
        "source_path": file_path,
        "file_type": header["file_type"],
        "format": header["format"],
        "format_ver": header["format_ver"],
        "file_size": file_size,
        "username": "",
        "file_object": None,  # 파서가 직접 open()으로 처리
        "_local_path": file_path,
        "_temp_path": None,
    })
    return results


# ─── 내부 유틸 ──────────────────────────────────────────────────────────────────

def _path_variants(path: str) -> list:
    variants = {path}
    parts = path.split("/")
    # 모두 소문자 버전
    variants.add("/".join(p.lower() for p in parts))
    return list(variants)