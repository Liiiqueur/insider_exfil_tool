import os
import tempfile


SPOOL_DIR = "/Windows/System32/spool/PRINTERS"


def collect_from_image(handler, fs):
    collected = []

    try:
        entries = handler.list_directory(fs, None, SPOOL_DIR)
    except Exception:
        return collected

    for entry in entries:
        if entry.is_dir:
            continue

        if not entry.name.lower().endswith((".spl", ".shd")):
            continue

        data = handler.read_file(fs, entry.inode, max_bytes=10 * 1024 * 1024)
        if not data:
            continue

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{entry.name}")
        tmp.write(data)
        tmp.close()

        collected.append({
            "artifact_name": "spool",
            "file_type": "SHD" if entry.name.lower().endswith(".shd") else "SPL",
            "file_name": entry.name,
            "source_path": entry.path,
            "temp_path": tmp.name,
            "size": entry.size,
            "inode": entry.inode,
        })

    return collected