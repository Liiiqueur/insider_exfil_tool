from collectors.artifact_utils import extract_path_to_temp, iso_now


J_TARGETS = (
    {"artifact_name": "$J", "source_path": "/$Extend/$UsnJrnl:$J", "max_bytes": 512 * 1024 * 1024},
    {"artifact_name": "$J", "source_path": "/$Extend/$UsnJrnl", "max_bytes": 512 * 1024 * 1024},
    {"artifact_name": "$J", "source_path": "/$Extend/$J", "max_bytes": 512 * 1024 * 1024},
)
def _collect_j(fs, collected_at: str, bucket: list[dict]) -> None:
    for target in J_TARGETS:
        tmp_path = extract_path_to_temp(
            fs,
            target["source_path"],
            suffix=f"_{target['artifact_name'].replace('$', '')}",
            max_bytes=target["max_bytes"],
        )
        if not tmp_path:
            continue
        bucket.append({
            "artifact_name": target["artifact_name"],
            "record_type": "raw_artifact",
            "source_path": target["source_path"],
            "tmp_path": tmp_path,
            "collected_at": collected_at,
        })
        return


def collect_from_image(handler, fs) -> list[dict]:
    results = []
    collected_at = iso_now()
    mft_tmp_path = extract_path_to_temp(fs, "/$MFT", suffix="_MFT", max_bytes=512 * 1024 * 1024)
    results.append({
        "artifact_name": "$MFT",
        "record_type": "raw_artifact",
        "source_path": "/$MFT",
        "tmp_path": mft_tmp_path,
        "collected_at": collected_at,
    })
    _collect_j(fs, collected_at, results)
    return results
