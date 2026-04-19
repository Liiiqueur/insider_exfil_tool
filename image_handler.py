from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Generator

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 선택적 의존성
# ──────────────────────────────────────────
try:
    import pytsk3
    _TSK_OK = True
except ImportError:
    _TSK_OK = False

try:
    import pyewf
    _EWF_OK = True
except ImportError:
    _EWF_OK = False


# ──────────────────────────────────────────
# 예외
# ──────────────────────────────────────────

class E01NotSupportedError(Exception):
    def __init__(self, path: str):
        super().__init__(f"E01 파일을 열 수 없습니다: {path}")

# ──────────────────────────────────────────
# EWF 래퍼 (pytsk3 + pyewf 둘 다 있을 때만 정의)
# ──────────────────────────────────────────

if _TSK_OK and _EWF_OK:
    class _EWFImgInfo(pytsk3.Img_Info):

        def __init__(self, ewf_handle):
            self._handle = ewf_handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset: int, length: int) -> bytes:
            self._handle.seek(offset)
            return self._handle.read(length)

        def get_size(self) -> int:
            return self._handle.get_media_size()
else:
    _EWFImgInfo = None


# ──────────────────────────────────────────
# 데이터 클래스
# ──────────────────────────────────────────

@dataclass
class FsEntry:
    name:          str
    path:          str
    is_dir:        bool
    size:          int    = 0
    inode:         int    = 0
    created_time:  datetime | None = None
    modified_time: datetime | None = None
    accessed_time: datetime | None = None
    changed_time:  datetime | None = None
    _fs:           object = field(default=None, repr=False)


# ──────────────────────────────────────────
# 내부 유틸
# ──────────────────────────────────────────

def _ts(unix_ts: int | float | None) -> datetime | None:
    if not unix_ts:
        return None
    try:
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


_EWF_EXTS = frozenset({".e01", ".ex01", ".ewf"})
_DEVICE_PREFIXES = ("\\\\.\\", "//./")


# ══════════════════════════════════════════
# ImageHandler
# ══════════════════════════════════════════

class ImageHandler:
    def __init__(self):
        self._img_info:   object       = None
        self._ewf_handle: object       = None
        self.image_path:  str          = ""
        self.volumes:     list[dict]   = []

    # ═══════════════════════════════════════
    # 공개 API — 열기
    # ═══════════════════════════════════════

    def open(self, path: str) -> None:
        if not _TSK_OK:
            raise ImportError(
                "pytsk3 가 설치되지 않았습니다.\n  pip install pytsk3"
            )
        self.image_path = path
        ext = os.path.splitext(path)[1].lower()

        if ext in _EWF_EXTS:
            self._open_ewf(path)
        elif any(path.startswith(prefix) for prefix in _DEVICE_PREFIXES):
            self._img_info = pytsk3.Img_Info(url=path)
        else:
            self._img_info = pytsk3.Img_Info(path)

        self.volumes = self._detect_volumes()
        logger.info("열기 완료: %s  볼륨 %d개", path, len(self.volumes))

    def close(self) -> None:
        if self._ewf_handle:
            try:
                self._ewf_handle.close()
            except Exception:
                pass

    # ═══════════════════════════════════════
    # 공개 API — 파일시스템 탐색
    # ═══════════════════════════════════════

    def list_directory(
        self,
        fs,
        inode: int | None = None,
        path: str = "/",
    ) -> list[FsEntry]:
        try:
            directory = (
                fs.open_dir(inode=inode) if inode is not None
                else fs.open_dir(path=path)
            )
        except Exception as e:
            logger.debug("디렉터리 열기 실패 path=%s: %s", path, e)
            return []

        entries: list[FsEntry] = []
        for f in directory:
            entry = self._parse_dir_entry(f, path, fs)
            if entry is not None:
                entries.append(entry)

        entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
        return entries

    def read_file(
        self,
        fs,
        inode: int,
        max_bytes: int = 1024 * 1024,
    ) -> bytes:
        try:
            f    = fs.open_meta(inode=inode)
            meta = getattr(f.info, "meta", None)
            if meta is None:
                return b""
            size = min(getattr(meta, "size", 0), max_bytes)
            return f.read_random(0, size) if size > 0 else b""
        except Exception as e:
            logger.warning("파일 읽기 실패 inode=%d: %s", inode, e)
            return b""

    # ═══════════════════════════════════════
    # 공개 API — 추출
    # ═══════════════════════════════════════

    def extract_entry(self, entry: FsEntry, destination_dir: str) -> int:
        if entry.is_dir:
            target_dir = self._unique_path(
                os.path.join(destination_dir, entry.name)
            )
            os.makedirs(target_dir, exist_ok=True)
            return self._extract_directory(
                entry._fs, entry.inode, entry.path, target_dir
            )
        target_path = self._unique_path(
            os.path.join(destination_dir, entry.name)
        )
        self._extract_file(entry._fs, entry.inode, target_path)
        return 1

    # ═══════════════════════════════════════
    # 공개 API — 아티팩트 검색
    # ═══════════════════════════════════════

    def find_ntuser_dat(self, fs) -> list[dict]:
        return list(self._search(fs, "/Users", "NTUSER.DAT", max_depth=3))

    # ═══════════════════════════════════════
    # 내부 — 열기
    # ═══════════════════════════════════════

    def _open_ewf(self, path: str) -> None:
        if not _EWF_OK:
            raise E01NotSupportedError(path)
        filenames         = pyewf.glob(path)
        handle            = pyewf.handle()
        handle.open(filenames)
        self._ewf_handle  = handle
        self._img_info    = _EWFImgInfo(handle)
        logger.info("EWF 열기 완료: %s", path)

    def _detect_volumes(self) -> list[dict]:
        volumes: list[dict] = []
        try:
            vol_info  = pytsk3.Volume_Info(self._img_info)
            block_sz  = vol_info.info.block_size
            for part in vol_info:
                if part.flags != pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    continue
                offset = part.start * block_sz
                desc   = part.desc.decode(errors="replace").strip() or f"Part @ {offset}"
                try:
                    fs = pytsk3.FS_Info(self._img_info, offset=offset)
                    volumes.append({"offset": offset, "desc": desc, "fs": fs})
                    logger.info("  볼륨: %s  offset=%d", desc, offset)
                except Exception as e:
                    logger.debug("  FS 열기 실패 (%s): %s", desc, e)
        except Exception:
            # 파티션 테이블이 없는 이미지 → 단일 볼륨으로 시도
            logger.info("파티션 테이블 없음 → 단일 볼륨 시도")
            try:
                fs = pytsk3.FS_Info(self._img_info)
                volumes.append({"offset": 0, "desc": "Single Volume", "fs": fs})
            except Exception as e:
                logger.error("단일 볼륨 열기 실패: %s", e)
        return volumes

    # ═══════════════════════════════════════
    # 내부 — 디렉터리 항목 파싱
    # ═══════════════════════════════════════

    @staticmethod
    def _parse_dir_entry(f, parent_path: str, fs) -> FsEntry | None:
        try:
            name = f.info.name.name.decode(errors="replace")
        except Exception:
            return None

        if name in (".", "..") or f.info.meta is None:
            return None

        meta   = f.info.meta
        is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR

        return FsEntry(
            name          = name,
            path          = f"{parent_path.rstrip('/')}/{name}",
            is_dir        = is_dir,
            size          = meta.size,
            inode         = meta.addr,
            created_time  = _ts(getattr(meta, "crtime", 0)),
            modified_time = _ts(getattr(meta, "mtime",  0)),
            accessed_time = _ts(getattr(meta, "atime",  0)),
            changed_time  = _ts(getattr(meta, "ctime",  0)),
            _fs           = fs,
        )

    # ═══════════════════════════════════════
    # 내부 — 추출
    # ═══════════════════════════════════════

    def _extract_directory(
        self,
        fs,
        inode: int,
        path: str,
        destination_dir: str,
    ) -> int:
        extracted = 0
        for child in self.list_directory(fs, inode=inode, path=path):
            if child.is_dir:
                child_dir = os.path.join(destination_dir, child.name)
                os.makedirs(child_dir, exist_ok=True)
                extracted += self._extract_directory(
                    child._fs, child.inode, child.path, child_dir
                )
            else:
                target = self._unique_path(
                    os.path.join(destination_dir, child.name)
                )
                self._extract_file(child._fs, child.inode, target)
                extracted += 1
        return extracted

    def _extract_file(
        self,
        fs,
        inode: int,
        destination_path: str,
        chunk_size: int = 1024 * 1024,
    ) -> None:
        file_obj = fs.open_meta(inode=inode)
        meta     = getattr(file_obj.info, "meta", None)
        size     = getattr(meta, "size", 0) if meta is not None else 0

        parent = os.path.dirname(destination_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(destination_path, "wb") as stream:
            offset = 0
            while offset < size:
                chunk = file_obj.read_random(offset, min(chunk_size, size - offset))
                if not chunk:
                    break
                stream.write(chunk)
                offset += len(chunk)

    # ═══════════════════════════════════════
    # 내부 — 아티팩트 검색
    # ═══════════════════════════════════════

    def _search(
        self,
        fs,
        dir_path: str,
        target: str,
        depth: int = 0,
        max_depth: int = 3,
    ) -> Generator[dict, None, None]:
        if depth > max_depth:
            return
        try:
            directory = fs.open_dir(path=dir_path)
        except Exception:
            return

        target_upper = target.upper()
        for f in directory:
            try:
                name = f.info.name.name.decode(errors="replace")
            except Exception:
                continue
            if name in (".", "..") or f.info.meta is None:
                continue

            full_path = f"{dir_path.rstrip('/')}/{name}"
            if f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                yield from self._search(
                    fs, full_path, target, depth + 1, max_depth
                )
            elif name.upper() == target_upper:
                yield {"path": full_path, "inode": f.info.meta.addr, "fs": fs}

    # ═══════════════════════════════════════
    # 내부 — 경로 유틸
    # ═══════════════════════════════════════

    @staticmethod
    def _unique_path(path: str) -> str:
        if not os.path.exists(path):
            return path
        base, ext = os.path.splitext(path)
        for index in range(1, 10_000):
            candidate = f"{base}_{index}{ext}"
            if not os.path.exists(candidate):
                return candidate
        raise FileExistsError(f"고유 경로 생성 실패: {path}")