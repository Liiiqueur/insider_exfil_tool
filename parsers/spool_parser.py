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
        if entry.get("file_type") != "SHD":
            continue

        try:
            with open(entry["temp_path"], "rb") as f:
                data = f.read()

            # SHD 구조 (간략 핵심)
            job_id = struct.unpack("<I", data[0:4])[0]

            # offset 기반 문자열 파싱
            user_offset = struct.unpack("<I", data[0x10:0x14])[0]
            doc_offset = struct.unpack("<I", data[0x14:0x18])[0]

            def read_utf16(offset):
                if offset == 0:
                    return ""
                s = data[offset:]
                end = s.find(b"\x00\x00")
                return s[:end].decode("utf-16le", errors="ignore")

            user = read_utf16(user_offset)
            document = read_utf16(doc_offset)

            # 시간 (대략 위치, 환경마다 다를 수 있음)
            try:
                time_raw = struct.unpack("<Q", data[0x18:0x20])[0]
                timestamp = _filetime_to_dt(time_raw)
            except:
                timestamp = None

            results.append({
                "artifact_name": "spool",
                "job_id": job_id,
                "user": user,
                "document_name": document,
                "timestamp": timestamp,
                "source_path": entry.get("source_path"),
                "file_name": entry.get("file_name"),
            })

        except Exception:
            continue

    return results