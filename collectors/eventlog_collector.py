from collectors.artifact_utils import WINDOWS_ROOT_CANDIDATES, extract_path_to_temp, first_existing_dir, iso_now


TARGET_LOGS = (
    "Security.evtx",
    "System.evtx",
    "Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
    "Microsoft-Windows-Kernel-PnP%4Configuration.evtx",
)


def collect_from_image(handler, fs) -> list[dict]:
    results = []
    windows_root = first_existing_dir(handler, fs, WINDOWS_ROOT_CANDIDATES)
    if not windows_root:
        return results
    logs_root = f"{windows_root}/System32/winevt/Logs"
    collected_at = iso_now()
    for filename in TARGET_LOGS:
        source_path = f"{logs_root}/{filename}"
        tmp_path = extract_path_to_temp(fs, source_path, suffix=f"_{filename}", max_bytes=256 * 1024 * 1024)
        if not tmp_path:
            continue
        results.append({"filename": filename, "source_path": source_path, "tmp_path": tmp_path, "collected_at": collected_at})
    return results
