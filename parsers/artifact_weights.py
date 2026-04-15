ARTIFACT_WEIGHTS = {
    "filesystem": {"label": "$MFT, $J", "frequency": 3, "probative": 3, "tamper_resistance": 3},
    "eventlog": {"label": "Event Log", "frequency": 3, "probative": 3, "tamper_resistance": 3},
    "lnk": {"label": "LNK", "frequency": 3, "probative": 2, "tamper_resistance": 2},
    "recentdocs": {"label": "RecentDocs", "frequency": 3, "probative": 2, "tamper_resistance": 1},
    "browser_artifacts": {"label": "Browser History", "frequency": 2, "probative": 2, "tamper_resistance": 1},
    "userassist": {"label": "UserAssist", "frequency": 2, "probative": 2, "tamper_resistance": 2},
    "jumplist": {"label": "Jumplist", "frequency": 3, "probative": 2, "tamper_resistance": 2},
    "shellbags": {"label": "Shellbags", "frequency": 3, "probative": 3, "tamper_resistance": 2},
    "mounteddevices": {"label": "MountedDevices", "frequency": 2, "probative": 3, "tamper_resistance": 3},
}


def get_artifact_weight(artifact_id: str) -> dict:
    info = ARTIFACT_WEIGHTS.get(artifact_id, {}).copy()
    if not info:
        return {"label": artifact_id, "frequency": 0, "probative": 0, "tamper_resistance": 0, "total": 0}
    info["total"] = info["frequency"] + info["probative"] + info["tamper_resistance"]
    return info


def attach_artifact_weight(entry: dict, artifact_id: str) -> dict:
    entry["artifact_weight"] = get_artifact_weight(artifact_id)
    return entry
