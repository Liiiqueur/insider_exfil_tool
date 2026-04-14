import os
import logging
from dataclasses import dataclass, field

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
    _fs:    object = field(default=None, repr=False)


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
                name=name, path=ch_path, is_dir=is_dir,
                size=f.info.meta.size, inode=f.info.meta.addr, _fs=fs,
            ))
        entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
        return entries

    def read_file(self, fs, inode: int, max_bytes: int = 1024 * 1024) -> bytes:
        try:
            f    = fs.open_meta(inode=inode)
            size = min(f.info.meta.size, max_bytes)
            return f.read_random(0, size)
        except Exception as e:
            logger.warning("파일 읽기 실패 inode=%d: %s", inode, e)
            return b""

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