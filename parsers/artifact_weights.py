ARTIFACT_WEIGHTS = {
    "userassist": {
        "label": "UserAssist",
        "frequency": 2,
        "probative": 2,
        "tamper_resistance": 2,
    },
    "jumplist": {
        "label": "Jumplist",
        "frequency": 3,
        "probative": 2,
        "tamper_resistance": 2,
    },
    "shellbags": {
        "label": "ShellBags",
        "frequency": 3,
        "probative": 3,
        "tamper_resistance": 2,
    },
    "prefetch": {
        "label": "Prefetch",
        "frequency": 2,
        "probative": 2,
        "tamper_resistance": 2,
    },
    "amcache": {
        "label": "Amcache",
        "frequency": 1,
        "probative": 2,
        "tamper_resistance": 3,
    },
    "outlook_store": {
        "label": "Outlook OST/PST",
        "frequency": 1,
        "probative": 3,
        "tamper_resistance": 2,
    },
    "printer_spool": {
        "label": "Printer Spool Log",
        "frequency": 1,
        "probative": 2,
        "tamper_resistance": 2,
    },
    "mounteddevices": {
        "label": "MountedDevices",
        "frequency": 2,
        "probative": 3,
        "tamper_resistance": 3,
    },
    "usb_registry": {
        "label": "USB Registry",
        "frequency": 2,
        "probative": 3,
        "tamper_resistance": 3,
    },
}


def get_artifact_weight(artifact_id: str) -> dict:
    info = ARTIFACT_WEIGHTS.get(artifact_id, {}).copy()
    if not info:
        return {
            "label": artifact_id,
            "frequency": 0,
            "probative": 0,
            "tamper_resistance": 0,
            "total": 0,
        }
    info["total"] = info["frequency"] + info["probative"] + info["tamper_resistance"]
    return info


def attach_artifact_weight(entry: dict, artifact_id: str) -> dict:
    entry["artifact_weight"] = get_artifact_weight(artifact_id)
    return entry
