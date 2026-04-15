import binascii

from parsers.artifact_weights import attach_artifact_weight

try:
    from Registry import Registry
    _REGISTRY_OK = True
except ImportError:
    _REGISTRY_OK = False


ROOT_KEY = "MountedDevices"


def _decode_data(raw_data: bytes) -> tuple[str, str]:
    if len(raw_data) == 12:
        disk_signature = binascii.hexlify(raw_data[:4]).decode("ascii")
        partition_offset = int.from_bytes(raw_data[4:], "little", signed=False)
        return "disk_signature", f"disk_signature={disk_signature} partition_offset={partition_offset}"
    try:
        text = raw_data.decode("utf-16-le").strip("\x00")
        if text:
            return "unicode_string", text
    except Exception:
        pass
    return "binary", binascii.hexlify(raw_data).decode("ascii")


def parse(collected: list[dict]) -> list[dict]:
    if not _REGISTRY_OK:
        raise ImportError("python-registry is required for MountedDevices parsing")
    results = []
    for info in collected:
        reg = Registry.Registry(info["tmp_path"])
        try:
            key = reg.open(ROOT_KEY)
        except Registry.RegistryKeyNotFoundException:
            continue
        for value in key.values():
            mapping_type, decoded_data = _decode_data(value.raw_data())
            results.append(attach_artifact_weight({"value_name": value.name(), "mapping_type": mapping_type, "decoded_data": decoded_data, "source_path": info["source_path"], "last_written_time": key.timestamp(), "collected_at": info["collected_at"]}, "mounteddevices"))
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    return []
