import tempfile

PREFETCH_DIR = "/Windows/Prefetch"


def collect_from_image(handler, fs):
    collected = []

    try:
        entries = handler.list_directory(fs, None, PREFETCH_DIR)
    except Exception:
        return collected

    for entry in entries:
        if entry.is_dir:
            continue

        if not entry.name.lower().endswith(".pf"):
            continue

        data = handler.read_file(fs, entry.inode, max_bytes=5 * 1024 * 1024)
        if not data:
            continue

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pf")
        tmp.write(data)
        tmp.close()

        collected.append({
            "artifact_name": "prefetch",
            "file_name": entry.name,
            "source_path": entry.path,
            "temp_path": tmp.name,
            "size": entry.size,
            "inode": entry.inode,
        })

    return collected