import logging
import os
import struct
from datetime import datetime, timedelta, timezone

from parsers.artifact_weights import attach_artifact_weight
from parsers.timeline_event import build_timeline_event, sort_timeline

logger = logging.getLogger(__name__)

_RECORD_SIZE = 1024
_ATTR_TYPE_STANDARD_INFORMATION = 0x10
_ATTR_TYPE_FILE_NAME = 0x30
_ATTR_TYPE_DATA = 0x80
_ATTR_TYPE_END = 0xFFFFFFFF
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_PARSED_MFT_CACHE = {}


def _filetime_to_dt(value: int):
    if not value:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except Exception:
        return None


def _safe_utf16le(data: bytes) -> str:
    try:
        return data.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return ""


def _raw_artifact_entry(info: dict) -> dict:
    try:
        size = os.path.getsize(info["tmp_path"]) if info.get("tmp_path") else None
    except OSError:
        size = None
    return attach_artifact_weight({
        "artifact_name": info["artifact_name"],
        "record_type": "raw_artifact",
        "source_path": info["source_path"],
        "size": size,
        "collected_at": info["collected_at"],
    }, "filesystem")


def _mft_record_entry(info: dict) -> dict:
    return attach_artifact_weight({
        "artifact_name": "$MFT",
        "record_type": "filesystem_record",
        "source_path": info.get("source_path", ""),
        "entry_name": info.get("entry_name"),
        "is_dir": bool(info.get("is_dir")),
        "is_deleted": bool(info.get("is_deleted")),
        "inode": info.get("inode"),
        "parent_inode": info.get("parent_inode"),
        "size": info.get("size"),
        "created_time": info.get("created_time"),
        "modified_time": info.get("modified_time"),
        "accessed_time": info.get("accessed_time"),
        "changed_time": info.get("changed_time"),
        "collected_at": info.get("collected_at"),
    }, "filesystem")


def parse(collected: list[dict]) -> list[dict]:
    results = []
    for info in collected:
        if info.get("artifact_name") == "$MFT" and info.get("record_type") == "raw_artifact":
            results.append(_raw_artifact_entry(info))
            results.extend(_parse_mft_records(info))
        else:
            results.append(_raw_artifact_entry(info))

    results.sort(
        key=lambda item: item.get("accessed_time") or item.get("modified_time") or item.get("created_time") or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    results.sort(
        key=lambda item: 0 if item.get("artifact_name") == "$MFT" and item.get("record_type") == "filesystem_record" else 1
    )
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    action_map = {
        "created_time": "file_created",
        "modified_time": "file_modified",
        "accessed_time": "file_accessed",
        "changed_time": "metadata_changed",
    }
    for entry in entries:
        if entry.get("artifact_name") != "$MFT" or entry.get("record_type") != "filesystem_record":
            continue
        for field_name, label in (
            ("created_time", "Created"),
            ("modified_time", "Modified"),
            ("accessed_time", "Accessed"),
            ("changed_time", "Changed"),
        ):
            timestamp = entry.get(field_name)
            if not timestamp:
                continue
            target = entry.get("source_path") or entry.get("entry_name") or ""
            timeline.append(build_timeline_event(
                timestamp=timestamp,
                artifact_type="filesystem",
                action=action_map[field_name],
                target=target,
                source="$MFT",
                summary=f"{label}: {target}",
                detail={
                    "inode": entry.get("inode"),
                    "parent_inode": entry.get("parent_inode"),
                    "size": entry.get("size"),
                    "is_dir": entry.get("is_dir"),
                    "is_deleted": entry.get("is_deleted"),
                    "entry_name": entry.get("entry_name"),
                    "source_path": entry.get("source_path"),
                },
            ))
    return sort_timeline(timeline)


def _parse_mft_records(info: dict) -> list[dict]:
    tmp_path = info.get("tmp_path")
    if not tmp_path or not os.path.exists(tmp_path):
        logger.warning("$MFT temp file is missing: %s", tmp_path)
        return []

    try:
        stat = os.stat(tmp_path)
        cache_key = (tmp_path, stat.st_size, int(stat.st_mtime))
    except OSError:
        cache_key = None

    if cache_key and cache_key in _PARSED_MFT_CACHE:
        return list(_PARSED_MFT_CACHE[cache_key])

    try:
        with open(tmp_path, "rb") as f:
            data = f.read()
    except OSError as exc:
        logger.warning("failed to read $MFT temp file (%s): %s", tmp_path, exc)
        return []

    records = {}
    for offset in range(0, len(data) - _RECORD_SIZE + 1, _RECORD_SIZE):
        raw_record = data[offset:offset + _RECORD_SIZE]
        record = _parse_record(raw_record, offset // _RECORD_SIZE)
        if not record:
            continue
        records[record["inode"]] = record

    if not records:
        logger.warning("no valid FILE records were parsed from $MFT: %s", tmp_path)
        return []

    path_cache = {}
    parsed_entries = []
    for inode in sorted(records.keys()):
        record = records[inode]
        source_path = _build_full_path(inode, records, path_cache)
        parsed_entries.append(_mft_record_entry({
            "source_path": source_path,
            "entry_name": record.get("entry_name"),
            "is_dir": record.get("is_dir"),
            "is_deleted": record.get("is_deleted"),
            "inode": inode,
            "parent_inode": record.get("parent_inode"),
            "size": record.get("size"),
            "created_time": record.get("created_time"),
            "modified_time": record.get("modified_time"),
            "accessed_time": record.get("accessed_time"),
            "changed_time": record.get("changed_time"),
            "collected_at": info.get("collected_at"),
        }))
    if cache_key:
        _PARSED_MFT_CACHE[cache_key] = list(parsed_entries)
    return parsed_entries


def _parse_record(raw_record: bytes, fallback_inode: int):
    if raw_record[:4] != b"FILE":
        return None

    record = _apply_fixup(raw_record)
    if not record:
        return None

    try:
        first_attr_offset = struct.unpack_from("<H", record, 20)[0]
        flags = struct.unpack_from("<H", record, 22)[0]
        used_size = struct.unpack_from("<I", record, 24)[0]
        inode = struct.unpack_from("<I", record, 44)[0] or fallback_inode
    except struct.error:
        return None

    is_in_use = bool(flags & 0x0001)
    is_dir = bool(flags & 0x0002)
    std_info = {}
    filename_attrs = []
    data_size = None

    cursor = first_attr_offset
    record_limit = min(len(record), used_size or len(record))
    while cursor + 8 <= record_limit:
        try:
            attr_type = struct.unpack_from("<I", record, cursor)[0]
        except struct.error:
            break
        if attr_type == _ATTR_TYPE_END:
            break
        try:
            attr_len = struct.unpack_from("<I", record, cursor + 4)[0]
            non_resident = record[cursor + 8]
            name_len = record[cursor + 9]
            name_offset = struct.unpack_from("<H", record, cursor + 10)[0]
        except Exception:
            break
        if attr_len < 24 or cursor + attr_len > len(record):
            break

        attr_name = ""
        if name_len and name_offset:
            name_start = cursor + name_offset
            name_end = name_start + name_len * 2
            attr_name = _safe_utf16le(record[name_start:name_end])

        if not non_resident:
            value_len = struct.unpack_from("<I", record, cursor + 16)[0]
            value_offset = struct.unpack_from("<H", record, cursor + 20)[0]
            value_start = cursor + value_offset
            value_end = value_start + value_len
            value = record[value_start:value_end]
            if attr_type == _ATTR_TYPE_STANDARD_INFORMATION:
                std_info = _parse_standard_information(value)
            elif attr_type == _ATTR_TYPE_FILE_NAME:
                filename_info = _parse_file_name(value)
                if filename_info:
                    filename_attrs.append(filename_info)
            elif attr_type == _ATTR_TYPE_DATA and not attr_name and data_size is None:
                data_size = value_len
        elif attr_type == _ATTR_TYPE_DATA and not attr_name and data_size is None:
            try:
                data_size = struct.unpack_from("<Q", record, cursor + 48)[0]
            except struct.error:
                pass
        cursor += attr_len

    if not filename_attrs:
        return None

    best_name = _select_best_filename_attr(filename_attrs)
    return {
        "inode": inode,
        "entry_name": best_name.get("name") or f"inode_{inode}",
        "parent_inode": best_name.get("parent_inode"),
        "is_dir": is_dir,
        "is_deleted": not is_in_use,
        "size": data_size if data_size is not None else best_name.get("real_size"),
        "created_time": std_info.get("created_time") or best_name.get("created_time"),
        "modified_time": std_info.get("modified_time") or best_name.get("modified_time"),
        "accessed_time": std_info.get("accessed_time") or best_name.get("accessed_time"),
        "changed_time": std_info.get("changed_time") or best_name.get("changed_time"),
        "names": filename_attrs,
    }


def _apply_fixup(raw_record: bytes):
    record = bytearray(raw_record)
    try:
        usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    except struct.error:
        return None
    if usa_offset <= 0 or usa_count <= 1:
        return bytes(record)

    usa_size = usa_count * 2
    if usa_offset + usa_size > len(record):
        return None

    update_sequence = record[usa_offset:usa_offset + usa_size]
    sequence_value = update_sequence[:2]
    replacements = [
        update_sequence[index:index + 2]
        for index in range(2, len(update_sequence), 2)
    ]

    for sector_index, replacement in enumerate(replacements, start=1):
        end = sector_index * 512
        if end > len(record):
            return None
        if record[end - 2:end] != sequence_value:
            return None
        record[end - 2:end] = replacement
    return bytes(record)


def _parse_standard_information(value: bytes) -> dict:
    if len(value) < 32:
        return {}
    try:
        created, modified, changed, accessed = struct.unpack_from("<QQQQ", value, 0)
    except struct.error:
        return {}
    return {
        "created_time": _filetime_to_dt(created),
        "modified_time": _filetime_to_dt(modified),
        "changed_time": _filetime_to_dt(changed),
        "accessed_time": _filetime_to_dt(accessed),
    }


def _parse_file_name(value: bytes):
    if len(value) < 66:
        return None
    try:
        parent_ref = struct.unpack_from("<Q", value, 0)[0]
        created, modified, changed, accessed = struct.unpack_from("<QQQQ", value, 8)
        alloc_size = struct.unpack_from("<Q", value, 40)[0]
        real_size = struct.unpack_from("<Q", value, 48)[0]
        name_length = value[64]
        namespace = value[65]
        name_bytes = value[66:66 + name_length * 2]
    except struct.error:
        return None

    return {
        "parent_inode": parent_ref & 0x0000FFFFFFFFFFFF,
        "created_time": _filetime_to_dt(created),
        "modified_time": _filetime_to_dt(modified),
        "changed_time": _filetime_to_dt(changed),
        "accessed_time": _filetime_to_dt(accessed),
        "allocated_size": alloc_size,
        "real_size": real_size,
        "namespace": namespace,
        "name": _safe_utf16le(name_bytes),
    }


def _select_best_filename_attr(filename_attrs: list[dict]) -> dict:
    priority = {1: 0, 3: 1, 0: 2, 2: 3}
    return sorted(
        filename_attrs,
        key=lambda item: (
            priority.get(item.get("namespace"), 99),
            item.get("name", "").lower(),
        ),
    )[0]


def _build_full_path(inode: int, records: dict, cache: dict, seen=None) -> str:
    if inode in cache:
        return cache[inode]
    if seen is None:
        seen = set()
    if inode in seen:
        path = f"/[cycle]/inode_{inode}"
        cache[inode] = path
        return path
    seen.add(inode)

    record = records.get(inode)
    if not record:
        path = f"/[missing]/inode_{inode}"
        cache[inode] = path
        return path

    name = record.get("entry_name") or f"inode_{inode}"
    if inode == 5 or name == ".":
        cache[inode] = "/"
        return "/"

    parent_inode = record.get("parent_inode")
    if not parent_inode or parent_inode == inode:
        path = f"/{name}"
        cache[inode] = path
        return path

    parent_path = _build_full_path(parent_inode, records, cache, seen)
    if parent_path == "/":
        path = f"/{name}"
    elif parent_path.startswith("/[missing]") or parent_path.startswith("/[cycle]"):
        path = f"/[orphan]/{name}"
    else:
        path = f"{parent_path.rstrip('/')}/{name}"
    cache[inode] = path
    return path
