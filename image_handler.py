import os
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

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


class E01NotSupportedError(Exception):
    """pyewf 없이 E01을 열려 할 때 발생."""
    pass


if _TSK_OK and _EWF_OK:
    class _EWFImgInfo(pytsk3.Img_Info):
        def __init__(self, ewf_handle):
            self._handle = ewf_handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
        def read(self, offset, length):
            self._handle.seek(offset)
            return self._handle.read(length)
        def get_size(self):
            return self._handle.get_media_size()
else:
    _EWFImgInfo = None


@dataclass
class FsEntry:
    name:   str
    path:   str
    is_dir: bool
    size:   int    = 0
    inode:  int    = 0
    created_time:  object = None
    modified_time: object = None
    accessed_time: object = None
    changed_time:  object = None
    _fs:    object = field(default=None, repr=False)


def _safe_unix_ts(timestamp):
    if not timestamp:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except Exception:
        return None


class ImageHandler:

    def __init__(self):
        self._img_info   = None
        self._ewf_handle = None
        self.image_path  = ""
        self.volumes: list[dict] = []

    def open(self, path: str) -> None:
        if not _TSK_OK:
            raise ImportError("pytsk3 가 설치되지 않았습니다.\n  pip install pytsk3")

        self.image_path = path
        ext = os.path.splitext(path)[1].lower()

        if ext in (".e01", ".ex01", ".ewf"):
            if not _EWF_OK:
                raise E01NotSupportedError(path)
            # pyewf로 열기
            filenames = pyewf.glob(path)
            handle = pyewf.handle()
            handle.open(filenames)
            self._ewf_handle = handle
            self._img_info = _EWFImgInfo(handle)
            logger.info("EWF 열기 완료: %s", path)
        elif path.startswith("\\\\.\\") or path.startswith("//./"):
            self._img_info = pytsk3.Img_Info(url=path)
        else:
            self._img_info = pytsk3.Img_Info(path)

        self.volumes = self._detect_volumes()
        logger.info("열기 완료: %s  볼륨 %d개", path, len(self.volumes))

    def _detect_volumes(self) -> list[dict]:
        volumes = []
        try:
            vol_info = pytsk3.Volume_Info(self._img_info)
            block    = vol_info.info.block_size
            for part in vol_info:
                if part.flags != pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    continue
                offset = part.start * block
                desc   = part.desc.decode(errors="replace").strip() or f"Part @ {offset}"
                try:
                    fs = pytsk3.FS_Info(self._img_info, offset=offset)
                    volumes.append({"offset": offset, "desc": desc, "fs": fs})
                    logger.info("  볼륨: %s  offset=%d", desc, offset)
                except Exception as e:
                    logger.debug("  FS 열기 실패 (%s): %s", desc, e)
        except Exception:
            logger.info("파티션 테이블 없음 → 단일 볼륨 시도")
            try:
                fs = pytsk3.FS_Info(self._img_info)
                volumes.append({"offset": 0, "desc": "Single Volume", "fs": fs})
            except Exception as e:
                logger.error("단일 볼륨 열기 실패: %s", e)
        return volumes

    def list_directory(self, fs, inode=None, path: str = "/") -> list[FsEntry]:
        entries = []
        try:
            if inode is not None:
                directory = fs.open_dir(inode=inode)
            else:
                # _search 와 동일하게 pytsk3 에 경로를 직접 전달 (단계 탐색보다 안정적)
                directory = fs.open_dir(path=path)
        except Exception as e:
            logger.debug("디렉터리 열기 실패 path=%s: %s", path, e)
            return entries
        for f in directory:
            try:
                name = f.info.name.name.decode(errors="replace")
            except Exception:
                continue
            if name in (".", "..") or f.info.meta is None:
                continue
            is_dir  = f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
            ch_path = f"{path.rstrip('/')}/{name}"
            entries.append(FsEntry(
                name=name,
                path=ch_path,
                is_dir=is_dir,
                size=f.info.meta.size,
                inode=f.info.meta.addr,
                created_time=_safe_unix_ts(getattr(f.info.meta, "crtime", 0)),
                modified_time=_safe_unix_ts(getattr(f.info.meta, "mtime", 0)),
                accessed_time=_safe_unix_ts(getattr(f.info.meta, "atime", 0)),
                changed_time=_safe_unix_ts(getattr(f.info.meta, "ctime", 0)),
                _fs=fs,
            ))
        entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
        return entries

    def read_file(self, fs, inode: int, max_bytes: int = 1024 * 1024) -> bytes:
        try:
            f = fs.open_meta(inode=inode)
            meta = getattr(f.info, "meta", None)
            if meta is None:
                return b""
            size = min(getattr(meta, "size", 0), max_bytes)
            if size <= 0:
                return b""
            return f.read_random(0, size)
        except Exception as e:
            logger.warning("파일 읽기 실패 inode=%d: %s", inode, e)
            return b""

    def extract_entry(self, entry: FsEntry, destination_dir: str) -> int:
        if entry.is_dir:
            target_dir = self._unique_destination(os.path.join(destination_dir, entry.name))
            os.makedirs(target_dir, exist_ok=True)
            return self._extract_directory(entry._fs, entry.inode, entry.path, target_dir)
        target_path = self._unique_destination(os.path.join(destination_dir, entry.name))
        self._extract_file(entry._fs, entry.inode, target_path)
        return 1

    def _extract_directory(self, fs, inode: int, path: str, destination_dir: str) -> int:
        extracted = 0
        for child in self.list_directory(fs, inode=inode, path=path):
            if child.is_dir:
                child_dir = os.path.join(destination_dir, child.name)
                os.makedirs(child_dir, exist_ok=True)
                extracted += self._extract_directory(child._fs, child.inode, child.path, child_dir)
                continue
            target_path = self._unique_destination(os.path.join(destination_dir, child.name))
            self._extract_file(child._fs, child.inode, target_path)
            extracted += 1
        return extracted

    def _extract_file(self, fs, inode: int, destination_path: str, chunk_size: int = 1024 * 1024) -> None:
        file_obj = fs.open_meta(inode=inode)
        meta = getattr(file_obj.info, "meta", None)
        size = getattr(meta, "size", 0) if meta is not None else 0
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        with open(destination_path, "wb") as stream:
            offset = 0
            while offset < size:
                to_read = min(chunk_size, size - offset)
                chunk = file_obj.read_random(offset, to_read)
                if not chunk:
                    break
                stream.write(chunk)
                offset += len(chunk)

    @staticmethod
    def _unique_destination(path: str) -> str:
        if not os.path.exists(path):
            return path
        base, ext = os.path.splitext(path)
        index = 1
        while True:
            candidate = f"{base}_{index}{ext}"
            if not os.path.exists(candidate):
                return candidate
            index += 1

    def find_ntuser_dat(self, fs) -> list[dict]:
        results = []
        self._search(fs, "/Users", "NTUSER.DAT", results, 0, 3)
        return results

    def _search(self, fs, dir_path, target, results, depth, max_depth):
        if depth > max_depth:
            return
        try:
            directory = fs.open_dir(path=dir_path)
        except Exception:
            return
        for f in directory:
            try:
                name = f.info.name.name.decode(errors="replace")
            except Exception:
                continue
            if name in (".", "..") or f.info.meta is None:
                continue
            full = f"{dir_path.rstrip('/')}/{name}"
            if f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                self._search(fs, full, target, results, depth + 1, max_depth)
            elif name.upper() == target.upper():
                results.append({"path": full, "inode": f.info.meta.addr, "fs": fs})

    def close(self):
        if self._ewf_handle:
            try:
                self._ewf_handle.close()
            except Exception:
                pass
