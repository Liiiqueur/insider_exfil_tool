import struct
from datetime import datetime, timezone


def _filetime_to_dt(filetime):
    if not filetime:
        return None
    return datetime.fromtimestamp(
        (filetime - 116444736000000000) / 10000000,
        tz=timezone.utc
    )


def parse(entries):
    results = []

    for entry in entries:
        try:
            with open(entry["temp_path"], "rb") as f:
                data = f.read()

            # ===== HEADER =====
            version = struct.unpack("<I", data[0:4])[0]
            signature = data[4:8]

            if signature != b"SCCA":
                continue  # invalid prefetch

            exe_name = data[0x10:0x10 + 60].decode("utf-16le", errors="ignore").strip("\x00")

            # ===== VERSION별 OFFSET =====
            if version in (17, 23):  # XP / 7
                run_count_offset = 0x90 if version == 17 else 0x98
                time_offset = 0x78 if version == 17 else 0x80
                timestamps_count = 1
            elif version in (26, 30):  # Win8+
                run_count_offset = 0xD0
                time_offset = 0x80
                timestamps_count = 8
            else:
                continue

            # ===== RUN COUNT =====
            run_count = struct.unpack("<I", data[run_count_offset:run_count_offset + 4])[0]

            # ===== TIMESTAMPS =====
            timestamps = []
            for i in range(timestamps_count):
                offset = time_offset + (i * 8)
                if offset + 8 > len(data):
                    break
                raw = struct.unpack("<Q", data[offset:offset + 8])[0]
                dt = _filetime_to_dt(raw)
                if dt:
                    timestamps.append(dt)

            last_run = timestamps[0] if timestamps else None

            results.append({
                "artifact_name": "prefetch",
                "executable": exe_name,
                "run_count": run_count,
                "last_run_time": last_run,
                "all_run_times": timestamps,
                "source_path": entry.get("source_path"),
                "file_name": entry.get("file_name"),
                "version": version,
            })

        except Exception:
            continue

    return results