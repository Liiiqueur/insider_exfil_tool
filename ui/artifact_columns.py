import os
from datetime import datetime, timezone


# ──────────────────────────────────────────
# 컬럼 정의
# ──────────────────────────────────────────

def get_columns(aid: str) -> list[tuple[str, str]]:
    _MAP: dict[str, list[tuple[str, str]]] = {
        "filesystem": [
            ("artifact",       "Artifact"),
            ("path",           "Path"),
            ("entry_type",     "Type"),
            ("size",           "Size"),
            ("inode",          "Inode"),
            ("created_time",   "Created Time"),
            ("modified_time",  "Modified Time"),
            ("accessed_time",  "Accessed Time"),
            ("changed_time",   "Changed Time"),
        ],
        "lnk": [
            ("user",        "User"),
            ("path",        "Path"),
            ("target_path", "Target Path"),
            ("last_access", "Last Access"),
        ],
        "eventlog": [
            ("event_id",    "Event ID"),
            ("channel",     "Channel"),
            ("provider",    "Provider"),
            ("timestamp",   "Timestamp"),
            ("description", "Description"),
        ],
        "recentdocs": [
            ("user",              "User"),
            ("document_name",     "Document"),
            ("extension",         "Extension"),
            ("last_written_time", "Last Written Time"),
        ],
        "browser_artifacts": [
            ("browser",       "Browser"),
            ("artifact_type", "Artifact Type"),
            ("profile",       "Profile"),
            ("url",           "URL / Path"),
            ("title",         "Title"),
            ("timestamp",     "Timestamp"),
        ],
        "userassist": [
            ("user",      "User"),
            ("name",      "Name"),
            ("run_count", "Run Count"),
            ("last_run",  "Last Run Time"),
        ],
        "jumplist": [
            ("appname",       "App"),
            ("category",      "Category"),
            ("target_path",   "Target Path"),
            ("access_count",  "Access Count"),
            ("last_access",   "Last Access"),
        ],
        "shellbags": [
            ("user",              "User"),
            ("path",              "Path"),
            ("last_written_time", "Last Written Time"),
        ],
        "mounteddevices": [
            ("value_name",   "Value Name"),
            ("mapping_type", "Mapping Type"),
            ("decoded_data", "Decoded Data"),
        ],
        "usb": [
            ("artifact_source",    "Source"),
            ("friendly_name",      "Friendly Name"),
            ("vendor",             "Vendor"),
            ("product",            "Product"),
            ("serial_number",      "Serial Number"),
            ("is_unique_serial",   "Unique S/N"),
            ("vendor_id",          "VID"),
            ("product_id",         "PID"),
            ("last_arrival_time",  "Last Connected"),
            ("last_removal_time",  "Last Removed"),
            ("first_install_time", "First Installed"),
            ("install_time",       "Install Date"),
        ],
        "spool": [
            ("job_id",        "Job ID"),
            ("user",          "User"),
            ("document_name", "Document"),
            ("timestamp",     "Timestamp"),
            ("source_path",   "Path"),
        ],
        "prefetch": [
            ("executable",    "Executable"),
            ("run_count",     "Run Count"),
            ("last_run_time", "Last Run"),
            ("source_path",   "Path"),
        ],
        "amcache": [
            ("file_name",    "File Name"),
            ("file_path",    "Path"),
            ("sha1",         "SHA1"),
            ("size",         "Size"),
            ("publisher",    "Publisher"),
            ("product",      "Product"),
            ("last_modified","Last Modified"),
        ],
        "ost_pst": [
            ("file_type",        "Type"),
            ("username",         "User"),
            ("folder_path",      "Folder"),
            ("item_type",        "Item Type"),
            ("subject",          "Subject"),
            ("sender_name",      "Sender"),
            ("sender_email",     "Sender Email"),
            ("recipients_to",    "To"),
            ("has_attachment",   "Attach?"),
            ("attachment_count", "# Att"),
            ("delivery_time",    "Delivery Time"),
            ("submit_time",      "Submit Time"),
            ("is_deleted",       "Deleted"),
            ("deletion_type",    "Del Type"),
            ("x_originating_ip", "Orig IP"),
            ("message_id",       "Message-ID"),
        ],
    }
    return _MAP.get(aid, [("value", "Value")])


# ──────────────────────────────────────────
# 행(row) 매핑
# ──────────────────────────────────────────

def get_row(
    aid: str,
    entry: dict,
    fmt_size,   # callable: (size) -> str
    fmt_dt,     # callable: (datetime | None) -> str
) -> dict:
    if aid == "filesystem":
        if (
            entry.get("artifact_name") == "$MFT"
            and entry.get("record_type") == "filesystem_record"
        ):
            return {
                "artifact":      "$MFT",
                "path":          entry.get("source_path", ""),
                "entry_type":    "Directory" if entry.get("is_dir") else "File",
                "size":          fmt_size(entry.get("size") or 0),
                "inode":         str(entry.get("inode") or ""),
                "created_time":  fmt_dt(entry.get("created_time")),
                "modified_time": fmt_dt(entry.get("modified_time")),
                "accessed_time": fmt_dt(entry.get("accessed_time")),
                "changed_time":  fmt_dt(entry.get("changed_time")),
            }
        return {
            "artifact":      entry.get("artifact_name", ""),
            "path":          entry.get("source_path", ""),
            "entry_type":    "Raw Artifact",
            "size":          fmt_size(entry.get("size") or 0),
            "inode":         "",
            "created_time":  "", "modified_time": "",
            "accessed_time": "", "changed_time":  "",
        }

    if aid == "lnk":
        return {
            "user":        entry.get("username", ""),
            "path":        entry.get("source_path", ""),
            "target_path": entry.get("target_path") or entry.get("name") or "",
            "last_access": fmt_dt(entry.get("access_time")),
        }

    if aid == "eventlog":
        return {
            "event_id":    str(entry.get("event_id") or ""),
            "channel":     entry.get("channel", ""),
            "provider":    entry.get("provider", ""),
            "timestamp":   fmt_dt(entry.get("timestamp")),
            "description": (
                entry.get("object_name")
                or entry.get("target_filename")
                or entry.get("device_description")
                or entry.get("new_process_name")
                or ""
            ),
        }

    if aid == "recentdocs":
        return {
            "user":             entry.get("username", ""),
            "document_name":    entry.get("document_name", ""),
            "extension":        entry.get("extension", ""),
            "last_written_time":fmt_dt(entry.get("last_written_time")),
        }

    if aid == "browser_artifacts":
        return {
            "browser":       entry.get("browser", ""),
            "artifact_type": entry.get("artifact_type", ""),
            "profile":       entry.get("profile", ""),
            "url":           entry.get("url") or entry.get("host") or entry.get("download_path") or "",
            "title":         entry.get("title") or entry.get("cookie_name") or "",
            "timestamp":     fmt_dt(entry.get("timestamp")),
        }

    if aid == "userassist":
        return {
            "user":      entry.get("username", ""),
            "name":      entry.get("name") or "",
            "run_count": str(entry.get("run_count") or ""),
            "last_run":  fmt_dt(entry.get("last_run_time")),
        }

    if aid == "jumplist":
        return {
            "appname":      entry.get("appname", ""),
            "category":     entry.get("category", ""),
            "target_path":  entry.get("target_path") or entry.get("name") or "",
            "access_count": str(entry.get("access_count") or ""),
            "last_access":  fmt_dt(entry.get("access_time")),
        }

    if aid == "shellbags":
        return {
            "user":             entry.get("username", ""),
            "path":             entry.get("shell_path", ""),
            "last_written_time":fmt_dt(entry.get("last_written_time")),
        }

    if aid == "mounteddevices":
        return {
            "value_name":   entry.get("value_name", ""),
            "mapping_type": entry.get("mapping_type", ""),
            "decoded_data": entry.get("decoded_data", ""),
        }

    if aid == "usb":
        return {
            "artifact_source":    entry.get("artifact_source", ""),
            "friendly_name":      entry.get("friendly_name", "") or entry.get("product", ""),
            "vendor":             entry.get("vendor", ""),
            "product":            entry.get("product", ""),
            "serial_number":      entry.get("serial_number", ""),
            "is_unique_serial":   "Yes" if entry.get("is_unique_serial") else "No (OS-generated)",
            "vendor_id":          entry.get("vendor_id", ""),
            "product_id":         entry.get("product_id", ""),
            "last_arrival_time":  fmt_dt(entry.get("last_arrival_time")),
            "last_removal_time":  fmt_dt(entry.get("last_removal_time")),
            "first_install_time": fmt_dt(entry.get("first_install_time")),
            "install_time":       fmt_dt(entry.get("install_time")),
        }

    if aid == "spool":
        return {
            "job_id":        str(entry.get("job_id", "")),
            "user":          entry.get("user", ""),
            "document_name": entry.get("document_name", ""),
            "timestamp":     fmt_dt(entry.get("timestamp")),
            "source_path":   entry.get("source_path", ""),
        }

    if aid == "prefetch":
        return {
            "executable":    entry.get("executable", ""),
            "run_count":     str(entry.get("run_count", "")),
            "last_run_time": fmt_dt(entry.get("last_run_time")),
            "source_path":   entry.get("source_path", ""),
        }

    if aid == "amcache":
        return {
            "file_name":    entry.get("file_name", ""),
            "file_path":    entry.get("file_path", ""),
            "sha1":         entry.get("sha1", ""),
            "size":         str(entry.get("size", "")),
            "publisher":    entry.get("publisher", ""),
            "product":      entry.get("product", ""),
            "last_modified":fmt_dt(entry.get("last_modified")),
        }

    if aid == "ost_pst":
        return {
            "file_type":        entry.get("file_type", ""),
            "username":         entry.get("username", ""),
            "folder_path":      entry.get("folder_path", ""),
            "item_type":        entry.get("item_type", ""),
            "subject":          entry.get("subject", ""),
            "sender_name":      entry.get("sender_name", ""),
            "sender_email":     entry.get("sender_email", ""),
            "recipients_to":    entry.get("recipients_to", ""),
            "has_attachment":   "Yes" if entry.get("has_attachment") else "",
            "attachment_count": str(entry.get("attachment_count") or ""),
            "delivery_time":    fmt_dt(entry.get("delivery_time")),
            "submit_time":      fmt_dt(entry.get("submit_time")),
            "is_deleted":       "Yes" if entry.get("is_deleted") else "",
            "deletion_type":    entry.get("deletion_type") or "",
            "x_originating_ip": entry.get("x_originating_ip", ""),
            "message_id":       entry.get("message_id", ""),
        }

    return {"value": str(entry)}


# ──────────────────────────────────────────
# 정렬 값
# ──────────────────────────────────────────

# 날짜 필드로 취급하는 키 집합
_TIMESTAMP_KEYS = frozenset({
    "created_time", "modified_time", "accessed_time", "changed_time",
    "install_time", "first_install_time", "last_arrival_time",
    "last_removal_time", "delivery_time", "submit_time", "creation_time",
})


def get_sort_value(entry: dict, key: str, display_value: str):
    if key in _TIMESTAMP_KEYS:
        ts = entry.get(key)
        return ts.timestamp() if ts else float("-inf")
    if key == "size":
        return entry.get("size") or 0
    if key == "inode":
        return entry.get("inode") or 0
    return (display_value or "").lower()


# ──────────────────────────────────────────
# 필터
# ──────────────────────────────────────────

_DOC_EXTS = frozenset({
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".hwp", ".hwpx", ".txt", ".csv",
})


def apply_filter(aid: str, entries: list[dict], filter_text: str) -> list[dict]:
    if aid != "filesystem" or filter_text == "전체":
        return entries

    cutoff = datetime.now(timezone.utc).timestamp() - 86_400  # 24 h
    filtered: list[dict] = []

    for entry in entries:
        if (
            entry.get("artifact_name") != "$MFT"
            or entry.get("record_type") != "filesystem_record"
        ):
            continue

        path = (entry.get("source_path") or "").lower()

        if filter_text == "휴지통만":
            if "/$recycle.bin/" in path:
                filtered.append(entry)

        elif filter_text == "문서 확장자만":
            if os.path.splitext(path)[1] in _DOC_EXTS:
                filtered.append(entry)

        elif filter_text == "최근 24시간만":
            timestamps = [
                entry.get("created_time"),
                entry.get("modified_time"),
                entry.get("accessed_time"),
                entry.get("changed_time"),
            ]
            if any(ts and ts.timestamp() >= cutoff for ts in timestamps):
                filtered.append(entry)

    return filtered


# ──────────────────────────────────────────
# 내보내기(텍스트)
# ──────────────────────────────────────────

def export_text(
    aid: str,
    entries: list[dict],
    artifact_label: str,
    artifact_desc: str,
    filter_text: str,
    fmt_size,
    fmt_dt,
) -> str:
    filtered  = apply_filter(aid, entries, filter_text)
    columns   = get_columns(aid)
    lines     = [artifact_label, artifact_desc, f"Entries: {len(filtered)}", ""]
    lines.append("\t".join(label for _, label in columns))
    for entry in filtered:
        mapped = get_row(aid, entry, fmt_size, fmt_dt)
        lines.append("\t".join(mapped.get(key, "") for key, _ in columns))
    return "\n".join(lines)