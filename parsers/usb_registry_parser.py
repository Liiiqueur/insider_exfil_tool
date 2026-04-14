from datetime import datetime, timezone

from parsers.artifact_weights import attach_artifact_weight

try:
    from Registry import Registry
    _REGISTRY_OK = True
except ImportError:
    _REGISTRY_OK = False


def _current_control_set(reg) -> str:
    try:
        select_key = reg.open("Select")
        current = select_key.value("Current").value()
        return f"ControlSet{int(current):03d}"
    except Exception:
        return "CurrentControlSet"


def _value_or_none(key, name: str):
    try:
        return key.value(name).value()
    except Exception:
        return None


def parse(collected: list[dict]) -> list[dict]:
    if not _REGISTRY_OK:
        raise ImportError("python-registry is required for USB registry parsing")

    results = []
    for info in collected:
        reg = Registry.Registry(info["tmp_path"])
        control_set = _current_control_set(reg)

        for branch in ("Enum\\USBSTOR", "Enum\\USB"):
            try:
                root = reg.open(f"{control_set}\\{branch}")
            except Registry.RegistryKeyNotFoundException:
                continue

            for device_key in root.subkeys():
                for instance_key in device_key.subkeys():
                    entry = {
                        "source_path": info["source_path"],
                        "registry_path": instance_key.path(),
                        "device_class": branch.split("\\")[-1],
                        "device_id": device_key.name(),
                        "serial_number": instance_key.name(),
                        "friendly_name": _value_or_none(instance_key, "FriendlyName"),
                        "service": _value_or_none(instance_key, "Service"),
                        "class_guid": _value_or_none(instance_key, "ClassGUID"),
                        "container_id": _value_or_none(instance_key, "ContainerID"),
                        "first_seen_time": instance_key.timestamp(),
                        "collected_at": info["collected_at"],
                    }
                    results.append(attach_artifact_weight(entry, "usb_registry"))

    results.sort(key=lambda item: item.get("first_seen_time") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for entry in entries:
        ts = entry.get("first_seen_time")
        if not ts:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        timeline.append({
            "timestamp": ts,
            "event_type": "usb_device",
            "source": f"USB Registry ({entry.get('device_class')})",
            "description": f"USB 장치 흔적: {entry.get('friendly_name') or entry.get('device_id')}",
            "detail": {
                "serial_number": entry.get("serial_number"),
                "service": entry.get("service"),
            },
        })
    return timeline
