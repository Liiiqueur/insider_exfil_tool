"""
AutomaticDestinations (CFB) 와 CustomDestinations (순차 LNK) 를 파싱한다.

의존 라이브러리:
    pip install olefile        # CFB (AutomaticDestinations) 파싱용

LNK 파일 구조 (MS-SHLLINK):
  0x00  4   HeaderSize (0x4C 고정)
  0x14  4   LinkFlags
  0x1C  8   CreationTime  (FILETIME)
  0x24  8   AccessTime    (FILETIME)
  0x2C  8   WriteTime     (FILETIME)
  0x34  4   FileSize
  → 이후 IDList / LinkInfo / StringData 가변 구조

AutomaticDestinations CFB 스트림:
  숫자 스트림 ("0","1",..) = 개별 LNK
  "DestList"              = 접근 시간/횟수 메타데이터

DestList 엔트리 구조:
  0x68  4   Entry ID  (숫자 스트림 이름과 매핑)
  0x70  8   마지막 접근 시간 (FILETIME)
  0x78  4   PIN 상태  (-1=비고정)
  0x7C  4   접근 횟수
  0x80  2   파일명 UTF-16 문자 수
  0x82  ?   파일명 (UTF-16 LE)
"""

import struct
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import olefile
    _OLE_OK = True
except ImportError:
    _OLE_OK = False

_FT_EPOCH = 116_444_736_000_000_000
_LNK_SIG  = b"\x4C\x00\x00\x00"

# LinkFlags
_HAS_IDLIST   = 1 << 0
_HAS_LINKINFO = 1 << 1
_HAS_NAME     = 1 << 2
_HAS_RELPATH  = 1 << 3
_HAS_WORKDIR  = 1 << 4
_HAS_ARGS     = 1 << 5
_HAS_ICONLOC  = 1 << 6
_IS_UNICODE   = 1 << 7


def _ft(raw: int) -> Optional[datetime]:
    if raw == 0:
        return None
    try:
        us = (raw - _FT_EPOCH) // 10
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + \
               __import__("datetime").timedelta(microseconds=us)
    except Exception:
        return None


# ── LNK 파서 ─────────────────────────────────────────────────────────────────

def parse_lnk(data: bytes) -> Optional[dict]:
    if len(data) < 0x4C or data[:4] != _LNK_SIG:
        return None
    try:
        link_flags    = struct.unpack_from("<I", data, 0x14)[0]
        creation_time = _ft(struct.unpack_from("<Q", data, 0x1C)[0])
        access_time   = _ft(struct.unpack_from("<Q", data, 0x24)[0])
        write_time    = _ft(struct.unpack_from("<Q", data, 0x2C)[0])
        file_size     = struct.unpack_from("<I", data, 0x34)[0]
        is_unicode    = bool(link_flags & _IS_UNICODE)

        pos = 0x4C

        # IDList 건너뛰기
        if link_flags & _HAS_IDLIST:
            if pos + 2 > len(data):
                return None
            pos += 2 + struct.unpack_from("<H", data, pos)[0]

        # LinkInfo → 로컬 경로 추출
        target_path = None
        if link_flags & _HAS_LINKINFO and pos + 28 <= len(data):
            base        = pos
            info_size   = struct.unpack_from("<I", data, base)[0]
            info_hdr_sz = struct.unpack_from("<I", data, base + 4)[0]
            info_flags  = struct.unpack_from("<I", data, base + 8)[0]
            lbp_off     = struct.unpack_from("<I", data, base + 16)[0]
            cps_off     = struct.unpack_from("<I", data, base + 24)[0]

            local_base = suffix = ""

            # ANSI 경로
            if info_flags & 0x1 and lbp_off:
                try:
                    p = base + lbp_off
                    e = data.index(b"\x00", p)
                    raw = data[p:e]
                    local_base = _safe_decode(raw)
                except:
                    pass

            if cps_off:
                try:
                    p = base + cps_off
                    e = data.index(b"\x00", p)
                    raw = data[p:e]
                    suffix = _safe_decode(raw)
                except:
                    pass

            # 🔥 Unicode 경로 (최우선)
            if info_hdr_sz >= 0x24 and base + 36 <= len(data):
                try:
                    ub_off = struct.unpack_from("<I", data, base + 28)[0]
                    us_off = struct.unpack_from("<I", data, base + 32)[0]

                    if ub_off:
                        p = base + ub_off
                        e = data.index(b"\x00\x00", p)
                        raw = data[p:e+2]
                        local_base = raw.decode("utf-16-le", errors="replace")

                    if us_off:
                        p = base + us_off
                        e = data.index(b"\x00\x00", p)
                        raw = data[p:e+2]
                        suffix = raw.decode("utf-16-le", errors="replace")

                except Exception:
                    pass

            target_path = (local_base + suffix).strip("\x00") or None
            pos += info_size

        # StringData
        def _read_str(p):
            count = struct.unpack_from("<H", data, p)[0]
            p += 2
            if is_unicode:
                s = data[p:p + count * 2].decode("utf-16-le", errors="replace")
                p += count * 2
            else:
                s = data[p:p + count].decode("latin-1", errors="replace")
                p += count
            return s, p

        name = rel_path = work_dir = arguments = icon_loc = ""
        try:
            if link_flags & _HAS_NAME    and pos < len(data): name,      pos = _read_str(pos)
            if link_flags & _HAS_RELPATH and pos < len(data): rel_path,  pos = _read_str(pos)
            if link_flags & _HAS_WORKDIR and pos < len(data): work_dir,  pos = _read_str(pos)
            if link_flags & _HAS_ARGS    and pos < len(data): arguments, pos = _read_str(pos)
            if link_flags & _HAS_ICONLOC and pos < len(data): icon_loc,  pos = _read_str(pos)
        except Exception:
            pass

        if not target_path and rel_path:
            target_path = rel_path

        return {
            "target_path":   target_path,
            "name":          name,
            "arguments":     arguments,
            "working_dir":   work_dir,
            "icon_location": icon_loc,
            "creation_time": creation_time,
            "access_time":   access_time,
            "write_time":    write_time,
            "file_size":     file_size,
        }
    except Exception as e:
        logger.debug("LNK 파싱 오류: %s", e)
        return None


# ── DestList 파서 ─────────────────────────────────────────────────────────────

def _parse_destlist(data: bytes) -> dict:
    result = {}
    if len(data) < 32:
        return result
    pos = 32   # 헤더 32바이트 건너뜀
    while pos + 0x82 <= len(data):
        try:
            entry_id     = struct.unpack_from("<I", data, pos + 0x68)[0]
            access_time  = _ft(struct.unpack_from("<Q", data, pos + 0x70)[0])
            pin_status   = struct.unpack_from("<i", data, pos + 0x78)[0]
            access_count = struct.unpack_from("<I", data, pos + 0x7C)[0]
            name_len     = struct.unpack_from("<H", data, pos + 0x80)[0]
            filename     = data[pos + 0x82: pos + 0x82 + name_len * 2].decode("utf-16-le", errors="replace")
            result[entry_id] = {
                "access_time":  access_time,
                "pin_status":   pin_status,
                "access_count": access_count,
                "filename":     filename,
            }
            pos += 0x82 + name_len * 2
        except Exception:
            break
    return result


# ── AutomaticDestinations ─────────────────────────────────────────────────────

def parse_automatic(info: dict) -> list[dict]:
    if not _OLE_OK:
        raise ImportError("olefile 이 설치되지 않았습니다.\n  pip install olefile")

    results   = []
    base_meta = {k: info[k] for k in
                 ("username","appid","appname","jl_type","filename","collected_at")}

    try:
        ole = olefile.OleFileIO(info["tmp_path"])
    except Exception as e:
        logger.error("CFB 열기 실패 [%s]: %s", info["tmp_path"], e)
        return results

    destlist_meta = {}
    if ole.exists("DestList"):
        try:
            destlist_meta = _parse_destlist(ole.openstream("DestList").read())
        except Exception as e:
            logger.warning("DestList 파싱 실패: %s", e)

    for stream in ole.listdir():
        name = stream[0] if isinstance(stream, list) else stream
        if not name.isdigit():
            continue
        try:
            entry_id = int(name)
            lnk      = parse_lnk(ole.openstream(name).read())
            if not lnk:
                continue
            dl = destlist_meta.get(entry_id, {})
            access_time = dl.get("access_time") or lnk["access_time"]
            results.append({
                **base_meta,
                "entry_id":      entry_id,
                "target_path":   lnk["target_path"],
                "name":          dl.get("filename") or lnk["name"],
                "arguments":     lnk["arguments"],
                "working_dir":   lnk["working_dir"],
                "access_time":   access_time,
                "creation_time": lnk["creation_time"],
                "write_time":    lnk["write_time"],
                "pin_status":    dl.get("pin_status", -1),
                "access_count":  dl.get("access_count", 0),
                "category":      "Pinned" if dl.get("pin_status", -1) >= 0 else "Recent",
            })
        except Exception as e:
            logger.debug("스트림 파싱 오류 [%s]: %s", name, e)

    ole.close()
    results.sort(
        key=lambda x: x["access_time"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    logger.info("[%s] AutomaticDestinations %d건", info["filename"], len(results))
    return results


# ── CustomDestinations ────────────────────────────────────────────────────────

def parse_custom(info: dict) -> list[dict]:
    results   = []
    base_meta = {k: info[k] for k in
                 ("username","appid","appname","jl_type","filename","collected_at")}
    try:
        with open(info["tmp_path"], "rb") as f:
            raw = f.read()
    except Exception as e:
        logger.error("파일 읽기 실패 [%s]: %s", info["tmp_path"], e)
        return results

    # LNK 시그니처 위치를 모두 찾아 슬라이싱
    offsets, start = [], 0
    while True:
        idx = raw.find(_LNK_SIG, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1

    for i, offset in enumerate(offsets):
        end = offsets[i + 1] if i + 1 < len(offsets) else len(raw)
        lnk = parse_lnk(raw[offset:end])
        if not lnk:
            continue
        results.append({
            **base_meta,
            "entry_id":      i,
            "target_path":   lnk["target_path"],
            "name":          lnk["name"],
            "arguments":     lnk["arguments"],
            "working_dir":   lnk["working_dir"],
            "access_time":   lnk["access_time"],
            "creation_time": lnk["creation_time"],
            "write_time":    lnk["write_time"],
            "pin_status":    -1,
            "access_count":  0,
            "category":      "Frequent/Tasks",
        })

    results.sort(
        key=lambda x: x["access_time"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    logger.info("[%s] CustomDestinations %d건", info["filename"], len(results))
    return results


# ── 공개 인터페이스 ───────────────────────────────────────────────────────────

def parse(collected: list[dict]) -> list[dict]:
    """
    collector 결과 전체를 받아 포맷을 자동 판별하고 파싱한다.
    """
    all_entries = []
    for info in collected:
        try:
            if info["jl_type"] == "AutomaticDestinations":
                all_entries.extend(parse_automatic(info))
            else:
                all_entries.extend(parse_custom(info))
        except Exception as e:
            logger.error("파싱 실패 [%s]: %s", info.get("filename"), e)

    all_entries.sort(
        key=lambda x: x["access_time"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    logger.info("Jumplist 파싱 완료 – 총 %d건", len(all_entries))
    return all_entries


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for e in entries:
        ts = e.get("access_time")
        if not ts:
            continue
        timeline.append({
            "timestamp":   ts,
            "event_type":  "file_access",
            "source":      f"Jumplist ({e['jl_type']})",
            "description": f"파일 접근: {e.get('target_path') or e.get('name') or '?'}",
            "detail": {
                "appname":      e["appname"],
                "appid":        e["appid"],
                "username":     e["username"],
                "category":     e["category"],
                "access_count": e["access_count"],
                "pin_status":   e["pin_status"],
                "arguments":    e.get("arguments"),
            },
        })
    timeline.sort(key=lambda x: x["timestamp"], reverse=True)
    return timeline