"""
image_handler.py  –  dd / raw / img / 분할(001~) 포맷 전용
"""
import os
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

try:
    import pytsk3
    _TSK_OK = True
except ImportError:
    _TSK_OK = False


SUPPORTED_EXTS = {".dd", ".raw", ".img", ".001"}


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
        self._img_info  = None
        self.image_path = ""
        self.volumes: list[dict] = []

    # ── 열기 ─────────────────────────────────────────────────────────────────

    def open(self, path: str) -> None:
        if not _TSK_OK:
            raise ImportError(
                "pytsk3 가 설치되지 않았습니다.\n"
                "  pip install pytsk3"
            )

        self.image_path = path
        ext = os.path.splitext(path)[1].lower()

        # 지원하지 않는 포맷 차단
        if ext in (".e01", ".ex01", ".ewf"):
            raise ValueError(
                "E01 포맷은 지원하지 않습니다.\n"
                "FTK Imager → Export Disk Image → Raw(dd) 로 변환 후 사용하세요."
            )

        # 물리 드라이브 직접 접근
        if path.startswith("\\\\.\\") or path.startswith("//./"):
            self._img_info = pytsk3.Img_Info(url=path)
            logger.info("물리 드라이브 열기: %s", path)

        elif ext == ".001":
            # 분할 이미지: 001, 002, 003... 자동 수집 후 첫 번째 세그먼트로 열기
            segments = self._collect_segments(path)
            logger.info("분할 이미지 %d개 발견: %s", len(segments), segments)
            self._img_info = pytsk3.Img_Info(path)
            logger.info("분할 이미지 열기: %s", path)

        else:
            if ext not in SUPPORTED_EXTS:
                logger.warning("알 수 없는 확장자 '%s' — dd 포맷으로 간주합니다.", ext)
            self._img_info = pytsk3.Img_Info(path)
            logger.info("dd 이미지 열기: %s", path)

        self.volumes = self._detect_volumes()
        logger.info("열기 완료: %s  볼륨 %d개", path, len(self.volumes))

    # ── 분할 세그먼트 수집 ────────────────────────────────────────────────────

    def _collect_segments(self, first_path: str) -> list[str]:
        """001, 002, 003... 세그먼트 파일 목록 반환"""
        base = os.path.splitext(first_path)[0]
        segments = []
        i = 1
        while True:
            seg = f"{base}.{i:03d}"
            if os.path.exists(seg):
                segments.append(seg)
                i += 1
            else:
                break
        return segments if segments else [first_path]

    # ── 볼륨 탐지 ────────────────────────────────────────────────────────────

    def _detect_volumes(self) -> list[dict]:
        volumes = []

        # 1) 파티션 테이블이 있는 경우 (MBR / GPT)
        try:
            vol_info = pytsk3.Volume_Info(self._img_info)
            block    = vol_info.info.block_size
            for part in vol_info:
                if part.flags != pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    continue
                offset = part.start * block
                desc   = (
                    part.desc.decode(errors="replace").strip()
                    or f"Partition @ offset {offset}"
                )
                try:
                    fs = pytsk3.FS_Info(self._img_info, offset=offset)
                    volumes.append({"offset": offset, "desc": desc, "fs": fs})
                    logger.info("  볼륨 발견: %s  (offset=%d)", desc, offset)
                except Exception as e:
                    logger.debug("  FS 열기 실패 (%s): %s", desc, e)

        # 2) 파티션 테이블 없음 → 단일 볼륨 시도
        except Exception:
            logger.info("파티션 테이블 없음 → 단일 볼륨으로 시도")
            try:
                fs = pytsk3.FS_Info(self._img_info)
                volumes.append({"offset": 0, "desc": "Single Volume", "fs": fs})
                logger.info("  단일 볼륨 열기 성공")
            except Exception as e:
                logger.error("단일 볼륨 열기 실패: %s", e)

        if not volumes:
            raise RuntimeError(
                "분석 가능한 파일시스템을 찾지 못했습니다.\n"
                "이미지 변환이 올바르게 됐는지 확인하세요."
            )

        return volumes

    # ── 디렉터리 목록 ─────────────────────────────────────────────────────────

    def list_directory(self, fs, inode=None, path: str = "/") -> list[FsEntry]:
        entries = []
        try:
            directory = (
                fs.open_dir(inode=inode)
                if inode is not None
                else fs.open_dir(path="/")
            )
        except Exception as e:
            logger.warning("디렉터리 열기 실패 inode=%s path=%s: %s", inode, path, e)
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
                name   = name,
                path   = ch_path,
                is_dir = is_dir,
                size   = f.info.meta.size,
                inode  = f.info.meta.addr,
                _fs    = fs,
            ))

        entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
        return entries

    # ── 파일 읽기 ────────────────────────────────────────────────────────────

    def read_file(self, fs, inode: int, max_bytes: int = 1024 * 1024) -> bytes:
        try:
            f    = fs.open_meta(inode=inode)
            size = min(f.info.meta.size, max_bytes)
            return f.read_random(0, size)
        except Exception as e:
            logger.warning("파일 읽기 실패 inode=%d: %s", inode, e)
            return b""

    # ── NTUSER.DAT 탐색 ───────────────────────────────────────────────────────

    def find_ntuser_dat(self, fs) -> list[dict]:
        results = []
        self._search(fs, "/Users", "NTUSER.DAT", results, depth=0, max_depth=3)
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
                results.append({
                    "path":  full,
                    "inode": f.info.meta.addr,
                    "fs":    fs,
                })
                logger.info("NTUSER.DAT 발견: %s", full)

    # ── 닫기 ─────────────────────────────────────────────────────────────────

    def close(self):
        self._img_info = None
        logger.info("이미지 핸들 닫기 완료")