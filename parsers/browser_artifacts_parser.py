import sqlite3
from datetime import datetime, timedelta, timezone

from parsers.artifact_weights import attach_artifact_weight


def _chromium_ts(value):
    if not value:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value))
    except Exception:
        return None


def _firefox_ts(value):
    if not value:
        return None
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value))
    except Exception:
        return None


def _query_rows(path: str, sql: str):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def _parse_chromium_history(info: dict) -> list[dict]:
    rows = _query_rows(info["tmp_path"], "SELECT urls.url, urls.title, urls.visit_count, urls.typed_count, visits.visit_time FROM visits JOIN urls ON urls.id = visits.url ORDER BY visits.visit_time DESC LIMIT 150")
    return [attach_artifact_weight({"username": info["username"], "browser": info["browser"], "profile": info["profile"], "artifact_type": "history", "url": row["url"], "title": row["title"], "visit_count": row["visit_count"], "typed_count": row["typed_count"], "timestamp": _chromium_ts(row["visit_time"]), "source_path": info["source_path"], "collected_at": info["collected_at"]}, "browser_artifacts") for row in rows]


def _parse_chromium_downloads(info: dict) -> list[dict]:
    try:
        rows = _query_rows(info["tmp_path"], "SELECT COALESCE(target_path, current_path) AS download_path, COALESCE(tab_url, '') AS tab_url, start_time, received_bytes, total_bytes FROM downloads ORDER BY start_time DESC LIMIT 100")
    except sqlite3.DatabaseError:
        return []
    return [attach_artifact_weight({"username": info["username"], "browser": info["browser"], "profile": info["profile"], "artifact_type": "download", "download_path": row["download_path"], "url": row["tab_url"], "received_bytes": row["received_bytes"], "total_bytes": row["total_bytes"], "timestamp": _chromium_ts(row["start_time"]), "source_path": info["source_path"], "collected_at": info["collected_at"]}, "browser_artifacts") for row in rows]


def _parse_chromium_cookies(info: dict) -> list[dict]:
    rows = _query_rows(info["tmp_path"], "SELECT host_key, name, path, creation_utc, last_access_utc, expires_utc, is_secure, is_httponly FROM cookies ORDER BY last_access_utc DESC LIMIT 150")
    return [attach_artifact_weight({"username": info["username"], "browser": info["browser"], "profile": info["profile"], "artifact_type": "cookie", "host": row["host_key"], "cookie_name": row["name"], "path": row["path"], "is_secure": bool(row["is_secure"]), "is_httponly": bool(row["is_httponly"]), "timestamp": _chromium_ts(row["last_access_utc"]) or _chromium_ts(row["creation_utc"]), "expires_time": _chromium_ts(row["expires_utc"]), "source_path": info["source_path"], "collected_at": info["collected_at"]}, "browser_artifacts") for row in rows]


def _parse_firefox_history(info: dict) -> list[dict]:
    rows = _query_rows(info["tmp_path"], "SELECT moz_places.url, moz_places.title, moz_places.visit_count, moz_historyvisits.visit_date FROM moz_historyvisits JOIN moz_places ON moz_places.id = moz_historyvisits.place_id ORDER BY moz_historyvisits.visit_date DESC LIMIT 150")
    return [attach_artifact_weight({"username": info["username"], "browser": info["browser"], "profile": info["profile"], "artifact_type": "history", "url": row["url"], "title": row["title"], "visit_count": row["visit_count"], "timestamp": _firefox_ts(row["visit_date"]), "source_path": info["source_path"], "collected_at": info["collected_at"]}, "browser_artifacts") for row in rows]


def _parse_firefox_cookies(info: dict) -> list[dict]:
    rows = _query_rows(info["tmp_path"], "SELECT host, name, path, creationTime, lastAccessed, expiry, isSecure, isHttpOnly FROM moz_cookies ORDER BY lastAccessed DESC LIMIT 150")
    return [attach_artifact_weight({"username": info["username"], "browser": info["browser"], "profile": info["profile"], "artifact_type": "cookie", "host": row["host"], "cookie_name": row["name"], "path": row["path"], "is_secure": bool(row["isSecure"]), "is_httponly": bool(row["isHttpOnly"]), "timestamp": _firefox_ts(row["lastAccessed"]) or _firefox_ts(row["creationTime"]), "expires_time": datetime.fromtimestamp(row["expiry"], tz=timezone.utc) if row["expiry"] else None, "source_path": info["source_path"], "collected_at": info["collected_at"]}, "browser_artifacts") for row in rows]


def parse(collected: list[dict]) -> list[dict]:
    results = []
    for info in collected:
        try:
            if info["browser"] in {"Chrome", "Edge"} and info["source_name"] == "History":
                results.extend(_parse_chromium_history(info))
                results.extend(_parse_chromium_downloads(info))
            elif info["browser"] in {"Chrome", "Edge"} and info["source_name"] == "Cookies":
                results.extend(_parse_chromium_cookies(info))
            elif info["browser"] == "Firefox" and info["source_name"] == "places.sqlite":
                results.extend(_parse_firefox_history(info))
            elif info["browser"] == "Firefox" and info["source_name"] == "cookies.sqlite":
                results.extend(_parse_firefox_cookies(info))
        except (sqlite3.DatabaseError, sqlite3.OperationalError):
            continue
    results.sort(key=lambda item: item.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return results


def parse_to_timeline(entries: list[dict]) -> list[dict]:
    timeline = []
    for entry in entries:
        if not entry.get("timestamp"):
            continue
        timeline.append({"timestamp": entry["timestamp"], "event_type": f"browser_{entry.get('artifact_type')}", "source": entry.get("browser"), "description": entry.get("url") or entry.get("host") or entry.get("download_path"), "detail": {"profile": entry.get("profile"), "artifact_type": entry.get("artifact_type")}})
    return timeline
