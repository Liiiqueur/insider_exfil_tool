import re
from datetime import datetime, timezone
from typing import Optional, Tuple

from parsers.artifact_weights import attach_artifact_weight


def _extract_strings(data: bytes) -> list[str]:
    ascii_hits = [match.decode("latin-1", errors="ignore").strip() for match in re.findall(rb"[\x20-\x7E]{4,}", data)]
    unicode_hits = []
    for match in re.findall(rb"(?:[\x20-\x7E]\x00){4,}", data):
        text = match.decode("utf-16-le", errors="ignore").strip("\x00 ").strip()
        if text:
            unicode_hits.append(text)
    return ascii_hits + unicode_hits


def _guess_printer_info(strings: list[str]) -> Tuple[Optional[str], Optional[str]]:
    printer_name = None
    document_name = None
    for text in strings:
        lower = text.lower()
        if not printer_name and ("printer" in lower or "microsoft print" in lower or "hp " in lower):
            printer_name = text
        if not document_name and any(token in lower for token in (".doc", ".pdf", ".ppt", ".xls", ".txt")):
            document_name = text
    return printer_name, document_name


def parse(collected: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for info in collected:
        entry = grouped.setdefault(info["job_id"], {
            "job_id": info["job_id"],
            "source_files": [],
            "printer_name": None,
            "document_name": None,
            "spool_format": None,
            "size_total": 0,
            "captured_strings": [],
            "collected_at": info["collected_at"],
        })

        entry["source_files"].append(info["source_path"])
        entry["size_total"] += info["size"]

        try:
            with open(info["tmp_path"], "rb") as stream:
                data = stream.read(4096)
        except OSError:
            data = b""

        strings = _extract_strings(data)
        entry["captured_strings"].extend(strings[:10])

        if info["extension"] == ".spl" and not entry["spool_format"]:
            if data.startswith(b"EMF"):
                entry["spool_format"] = "EMF"
            elif b"PCL" in data[:128]:
                entry["spool_format"] = "PCL"
            else:
                entry["spool_format"] = "RAW"

        printer_name, document_name = _guess_printer_info(strings)
        if printer_name and not entry["printer_name"]:
            entry["printer_name"] = printer_name
        if document_name and not entry["document_name"]:
            entry["document_name"] = document_name

    results = []
    for job_id, entry in grouped.items():
        if not entry["document_name"]:
            entry["document_name"] = f"Print Job {job_id}"
        entry["captured_strings"] = list(dict.fromkeys(entry["captured_strings"]))[:10]
        entry["source_path"] = ", ".join(entry["source_files"])
        results.append(attach_artifact_weight(entry, "printer_spool"))

    results.sort(key=lambda item: item["job_id"], reverse=True)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    now = datetime.now(timezone.utc)
    timeline = []
    for entry in entries:
        timeline.append({
            "timestamp": now,
            "event_type": "print_activity",
            "source": "Printer Spool",
            "description": f"인쇄 작업 흔적: {entry.get('document_name')}",
            "detail": {
                "printer_name": entry.get("printer_name"),
                "spool_format": entry.get("spool_format"),
            },
        })
    return timeline
