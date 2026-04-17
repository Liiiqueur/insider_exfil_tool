import tempfile

AMC_PATH = "/Windows/AppCompat/Programs/Amcache.hve"


def collect_from_image(handler, fs):
    collected = []

    try:
        entries = handler.list_directory(fs, None, "/Windows/AppCompat/Programs")
    except Exception:
        return collected

    for entry in entries:
        if entry.is_dir:
            continue

        if entry.name.lower().startswith("amcache.hve"):
            data = handler.read_file(fs, entry.inode, max_bytes=50 * 1024 * 1024)
            if not data:
                continue

            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".hve")
            tmp.write(data)
            tmp.close()

            collected.append({
                "artifact_name": "amcache",
                "file_name": entry.name,
                "source_path": entry.path,
                "temp_path": tmp.name,
                "size": entry.size,
                "inode": entry.inode,
            })

    return collected