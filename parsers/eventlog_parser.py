import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from parsers.artifact_weights import attach_artifact_weight

try:
    from Evtx.Evtx import Evtx
    _EVTX_OK = True
except ImportError:
    _EVTX_OK = False


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
TARGET_EVENT_IDS = {4624, 4634, 4647, 4656, 4660, 4663, 4688, 6416}


def _parse_system_time(value: str):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def _event_data_map(root: ET.Element) -> dict:
    result = {}
    for index, node in enumerate(root.findall("e:EventData/e:Data", NS)):
        key = node.attrib.get("Name") or f"Data{index}"
        result[key] = "".join(node.itertext()).strip()
    return result


def _parse_evtx_file(info: dict) -> list[dict]:
    results = []
    with Evtx(info["tmp_path"]) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            system = root.find("e:System", NS)
            if system is None:
                continue
            try:
                event_id = int(system.findtext("e:EventID", default="0", namespaces=NS))
            except ValueError:
                continue
            if event_id not in TARGET_EVENT_IDS:
                continue
            time_node = system.find("e:TimeCreated", NS)
            provider_node = system.find("e:Provider", NS)
            event_data = _event_data_map(root)
            results.append(attach_artifact_weight({
                "event_id": event_id,
                "channel": system.findtext("e:Channel", default="", namespaces=NS),
                "computer": system.findtext("e:Computer", default="", namespaces=NS),
                "provider": provider_node.attrib.get("Name", "") if provider_node is not None else "",
                "record_id": system.findtext("e:EventRecordID", default="", namespaces=NS),
                "timestamp": _parse_system_time(time_node.attrib.get("SystemTime", "") if time_node is not None else ""),
                "subject_user_name": event_data.get("SubjectUserName"),
                "object_name": event_data.get("ObjectName"),
                "new_process_name": event_data.get("NewProcessName"),
                "target_filename": event_data.get("TargetFilename"),
                "device_description": event_data.get("DeviceDescription"),
                "event_data": event_data,
                "source_log": info["filename"],
                "source_path": info["source_path"],
                "collected_at": info["collected_at"],
            }, "eventlog"))
    return results


def parse(collected: list[dict]) -> list[dict]:
    if not _EVTX_OK:
        return [attach_artifact_weight({"event_id": None, "channel": info["filename"], "provider": "EVTX parser unavailable", "timestamp": None, "source_log": info["filename"], "source_path": info["source_path"], "event_data": {}, "collected_at": info["collected_at"]}, "eventlog") for info in collected]
    results = []
    for info in collected:
        results.extend(_parse_evtx_file(info))
    results.sort(key=lambda item: item.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for entry in entries:
        if not entry.get("timestamp"):
            continue
        timeline.append({"timestamp": entry["timestamp"], "event_type": f"event_{entry.get('event_id')}", "source": entry.get("channel") or "Event Log", "description": entry.get("object_name") or entry.get("target_filename") or entry.get("new_process_name") or entry.get("device_description") or f"Event {entry.get('event_id')}", "detail": entry.get("event_data", {})})
    return timeline
