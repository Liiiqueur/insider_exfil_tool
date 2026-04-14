import binascii
import struct
from datetime import timezone

from parsers.artifact_weights import attach_artifact_weight

try:
    from Registry import Registry
    _REGISTRY_OK = True
except ImportError:
    _REGISTRY_OK = False


def _decode_binary(raw: bytes) -> str:
    # NOTE: 12-byte values usually store disk signature + partition offset.
    if len(raw) == 12:
        disk_signature = struct.unpack_from("<I", raw, 0)[0]
        partition_offset = struct.unpack_from("<Q", raw, 4)[0]
        return f"disk_signature=0x{disk_signature:08X}, partition_offset=0x{partition_offset:016X}"

    try:
        text = raw.decode("utf-16-le", errors="ignore").strip("\x00")
        if text and sum(1 for ch in text if ch.isprintable()) >= max(len(text) - 2, 1):
            return text
    except Exception:
        pass
    return "hex=" + binascii.hexlify(raw[:32]).decode("ascii")


def parse(collected: list[dict]) -> list[dict]:
    if not _REGISTRY_OK:
        raise ImportError("python-registry is required for MountedDevices parsing")

    results = []
    for info in collected:
        reg = Registry.Registry(info["tmp_path"])
        key = reg.open("MountedDevices")
        for value in key.values():
            raw = value.raw_data()
            entry = {
                "source_path": info["source_path"],
                "value_name": value.name(),
                "mapping_type": "dos_device" if value.name().startswith("\\DosDevices\\") else "volume_guid",
                "decoded_data": _decode_binary(raw),
                "binary_size": len(raw),
                "last_written_time": key.timestamp(),
                "collected_at": info["collected_at"],
            }
            results.append(attach_artifact_weight(entry, "mounteddevices"))

    results.sort(key=lambda item: item["value_name"])
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for entry in entries:
        ts = entry.get("last_written_time")
        if not ts:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        timeline.append({
            "timestamp": ts,
            "event_type": "device_mapping",
            "source": "MountedDevices",
            "description": f"볼륨 매핑 흔적: {entry.get('value_name')}",
            "detail": {
                "decoded_data": entry.get("decoded_data"),
            },
        })
    return timeline
