import os
import struct
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from parsers.artifact_weights import attach_artifact_weight

logger = logging.getLogger(__name__)

try:
    import pyscca
    _SCCA_OK = True
except ImportError:
    _SCCA_OK = False


_FILETIME_EPOCH = 116_444_736_000_000_000


def _filetime_to_dt(raw_value: int):
    if not raw_value:
        return None
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=(raw_value - _FILETIME_EPOCH) // 10)
    except Exception:
        return None


def _decode_prefetch_name(raw: bytes) -> str:
    return raw.decode("utf-16-le", errors="ignore").split("\x00", 1)[0].strip()


def _parse_with_pyscca(info: dict) -> Optional[dict]:
    store = pyscca.file()
    try:
        store.open(info["tmp_path"])
        last_run_times = []
        for index in range(getattr(store, "number_of_last_run_times", 0)):
            timestamp = store.get_last_run_time_as_integer(index)
            if timestamp:
                last_run_times.append(_filetime_to_dt(timestamp))

        entry = {
            "filename": info["filename"],
            "source_path": info["source_path"],
            "executable_name": store.executable_filename,
            "format_version": store.format_version,
            "run_count": store.run_count,
            "last_run_time": next((value for value in last_run_times if value), None),
            "last_run_times": [value for value in last_run_times if value],
            "prefetch_hash": getattr(store, "prefetch_hash", None),
            "volume_count": getattr(store, "number_of_volumes", 0),
            "collected_at": info["collected_at"],
        }
        return attach_artifact_weight(entry, "prefetch")
    except Exception as exc:
        logger.debug("pyscca parse failed for %s: %s", info["filename"], exc)
        return None
    finally:
        try:
            store.close()
        except Exception:
            pass


def _parse_fallback(info: dict) -> Optional[dict]:
    try:
        with open(info["tmp_path"], "rb") as stream:
            data = stream.read()
    except OSError:
        return None

    if len(data) < 84:
        return None

    signature = data[4:8]
    if signature not in (b"SCCA", b"MAM\x04"):
        return None

    version = struct.unpack_from("<I", data, 0)[0]
    executable_name = _decode_prefetch_name(data[16:76]) or os.path.splitext(info["filename"])[0]
    run_count = None
    for offset in (0x90, 0x98, 0xD0):
        if len(data) >= offset + 4:
            value = struct.unpack_from("<I", data, offset)[0]
            if value:
                run_count = value
                break

    last_run_times = []
    for offset in (0x80, 0x78):
        if len(data) >= offset + 8:
            timestamp = _filetime_to_dt(struct.unpack_from("<Q", data, offset)[0])
            if timestamp:
                last_run_times.append(timestamp)
                break

    entry = {
        "filename": info["filename"],
        "source_path": info["source_path"],
        "executable_name": executable_name,
        "format_version": version,
        "run_count": run_count,
        "last_run_time": last_run_times[0] if last_run_times else None,
        "last_run_times": last_run_times,
        "prefetch_hash": None,
        "volume_count": None,
        "collected_at": info["collected_at"],
    }
    return attach_artifact_weight(entry, "prefetch")


def parse(collected: list[dict]) -> list[dict]:
    results = []
    for info in collected:
        entry = None
        if _SCCA_OK:
            entry = _parse_with_pyscca(info)
        if not entry:
            entry = _parse_fallback(info)
        if entry:
            results.append(entry)

    results.sort(key=lambda item: item.get("last_run_time") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for entry in entries:
        if not entry.get("last_run_time"):
            continue
        timeline.append({
            "timestamp": entry["last_run_time"],
            "event_type": "program_execution",
            "source": "Prefetch",
            "description": f"프로그램 실행 흔적: {entry.get('executable_name')}",
            "detail": {
                "run_count": entry.get("run_count"),
                "source_path": entry.get("source_path"),
            },
        })
    return timeline
