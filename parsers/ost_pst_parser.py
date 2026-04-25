from __future__ import annotations

import email as email_lib
import email.policy
import logging
import os
import re
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 상수
# ──────────────────────────────────────────

_SOFT_DELETE_FOLDERS = frozenset({
    "deleted items", "deleted messages", "삭제된 항목", "trash", "bin",
})
_HARD_DELETE_FOLDERS = frozenset({
    "recoverable items", "purges", "deletions",
    "calendar logging", "audits", "복구 가능한 항목", "purge",
})

# 메시지 클래스 접두사 → item_type (순서 중요: 구체적인 것 먼저)
_ITEM_TYPE_MAP: list[tuple[str, str]] = [
    ("ipm.appointment", "calendar"),
    ("ipm.contact",     "contact"),
    ("ipm.task",        "task"),
    ("ipm.stickynote",  "note"),
    ("ipm.activity",    "journal"),
    ("ipm.note",        "email"),
    ("ipm.",            "email"),
]

# 폴더 이름 키워드 → item_type (message_class 없을 때 휴리스틱)
_FOLDER_TYPE_HINTS: list[tuple[str, str]] = [
    ("calendar", "calendar"),
    ("칼렌더",   "calendar"),
    ("일정",     "calendar"),
    ("contact",  "contact"),
    ("연락처",   "contact"),
    ("task",     "task"),
    ("작업",     "task"),
    ("note",     "note"),
    ("메모",     "note"),
]

MAX_MESSAGES_PER_FOLDER = 500
BODY_PREVIEW_LEN        = 256


# ──────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────

def parse(raw_items: list[dict]) -> list[dict]:
    if not raw_items:
        return []

    all_entries: list[dict] = []
    for raw_item in raw_items:
        all_entries.extend(_parse_pff_file(raw_item))

    all_entries.sort(key=_sort_key, reverse=True)

    logger.info(
        "OST/PST 전체 파싱 완료: 파일 %d개 → 총 %d개 항목 (삭제 포함 %d개)",
        len(raw_items),
        len(all_entries),
        sum(1 for e in all_entries if e.get("is_deleted")),
    )
    return all_entries


# ──────────────────────────────────────────
# 내부 — PFF 파일 파싱
# ──────────────────────────────────────────

def _parse_pff_file(raw_item: dict) -> list[dict]:
    try:
        import pypff
    except ImportError:
        logger.error("pypff 를 찾을 수 없습니다.\n  pip install libpff-python")
        return []

    pff_file = pypff.file()
    results: list[dict] = []

    try:
        _open_pff(pff_file, raw_item)
        logger.info(
            "PST/OST 파싱 시작: %s [%s %s %.1f MB]",
            raw_item["source_path"],
            raw_item["file_type"],
            raw_item["format"],
            raw_item["file_size"] / (1024 * 1024),
        )

        root = _safe_call(pff_file.get_root_folder)
        if root:
            _walk_folder(root, "/", raw_item, results)

        _collect_orphans(pff_file, raw_item, results, pypff)

        logger.info(
            "PST/OST 파싱 완료: %s → %d 개 항목",
            raw_item["source_path"], len(results),
        )
    except Exception as exc:
        logger.warning("PST/OST 파일 파싱 실패 [%s]: %s", raw_item.get("source_path"), exc)
    finally:
        try:
            pff_file.close()
        except Exception:
            pass

    return results


def _open_pff(pff_file, raw_item: dict) -> None:
    file_obj   = raw_item.get("file_object")
    local_path = raw_item.get("_local_path")
    if file_obj is not None:
        pff_file.open_file_object(file_obj)
    elif local_path and os.path.isfile(local_path):
        pff_file.open(local_path)
    else:
        raise FileNotFoundError(
            f"열 수 있는 파일 소스가 없음: {raw_item.get('source_path')}"
        )


def _collect_orphans(pff_file, raw_item: dict, results: list[dict], pypff) -> None:
    try:
        orphan_count = pff_file.get_number_of_orphan_items()
        recovered    = 0
        for i in range(orphan_count):
            try:
                item = pff_file.get_orphan_item(i)
                if item is None or not isinstance(item, pypff.message):
                    continue
                entry = _parse_single_message(
                    item, "/Orphan", "Orphan", raw_item,
                    is_deleted=True, deletion_type="orphan",
                )
                if entry:
                    results.append(entry)
                    recovered += 1
            except Exception:
                continue
        if recovered:
            logger.info("Orphan 복구 항목: %d 개", recovered)
    except Exception as exc:
        logger.debug("Orphan 처리 오류: %s", exc)


# ──────────────────────────────────────────
# 내부 — 폴더 순회
# ──────────────────────────────────────────

def _is_deleted_folder(folder_name: str) -> tuple[bool, str | None]:
    lower = folder_name.lower()
    if any(lower == n or lower.startswith(n) for n in _HARD_DELETE_FOLDERS):
        return True, "hard"
    if any(lower == n or lower.startswith(n) for n in _SOFT_DELETE_FOLDERS):
        return True, "soft"
    return False, None


def _walk_folder(
    folder,
    folder_path: str,
    source_info: dict,
    results: list[dict],
    parent_deleted: bool = False,
    parent_deletion_type: str | None = None,
    depth: int = 0,
    max_depth: int = 30,
) -> None:
    if depth > max_depth:
        logger.debug("최대 폴더 깊이 초과: %s", folder_path)
        return

    folder_name   = _safe_attr(folder, "name") or folder_path.rsplit("/", 1)[-1] or "Unknown"
    f_deleted, f_dtype = _is_deleted_folder(folder_name)
    is_deleted    = parent_deleted or f_deleted
    deletion_type = parent_deletion_type or f_dtype

    _process_folder_messages(folder, folder_path, folder_name, source_info, results, is_deleted, deletion_type)
    _process_sub_folders(folder, folder_path, source_info, results, is_deleted, deletion_type, depth, max_depth)


def _process_folder_messages(
    folder,
    folder_path: str,
    folder_name: str,
    source_info: dict,
    results: list[dict],
    is_deleted: bool,
    deletion_type: str | None,
) -> None:
    msg_count = _safe_call(lambda: folder.number_of_sub_messages) or 0
    cap       = min(msg_count, MAX_MESSAGES_PER_FOLDER)

    for i in range(cap):
        try:
            msg = folder.get_sub_message(i)
            if msg is None:
                continue
            entry = _parse_single_message(
                msg, folder_path, folder_name, source_info, is_deleted, deletion_type
            )
            if entry:
                results.append(entry)
        except Exception as exc:
            logger.debug("메시지 #%d 오류 [%s]: %s", i, folder_path, exc)

    if msg_count > MAX_MESSAGES_PER_FOLDER:
        logger.info(
            "폴더 '%s': %d/%d 메시지만 파싱 (MAX_MESSAGES_PER_FOLDER 제한)",
            folder_path, cap, msg_count,
        )


def _process_sub_folders(
    folder,
    folder_path: str,
    source_info: dict,
    results: list[dict],
    is_deleted: bool,
    deletion_type: str | None,
    depth: int,
    max_depth: int,
) -> None:
    sub_count = _safe_call(lambda: folder.number_of_sub_folders) or 0
    for i in range(sub_count):
        try:
            sub      = folder.get_sub_folder(i)
            if sub is None:
                continue
            sub_name = _safe_attr(sub, "name") or f"folder_{i}"
            _walk_folder(
                sub, f"{folder_path}/{sub_name}", source_info, results,
                is_deleted, deletion_type, depth + 1, max_depth,
            )
        except Exception as exc:
            logger.debug("하위폴더 #%d 오류 [%s]: %s", i, folder_path, exc)


# ──────────────────────────────────────────
# 내부 — 단일 메시지 파싱
# ──────────────────────────────────────────

def _parse_single_message(
    message,
    folder_path: str,
    folder_name: str,
    source_info: dict,
    is_deleted: bool,
    deletion_type: str | None,
) -> dict | None:
    try:
        subject     = _safe_attr(message, "subject")     or ""
        sender_name = _safe_attr(message, "sender_name") or ""

        delivery_time = _to_utc(_safe_attr(message, "delivery_time"))
        submit_time   = _to_utc(_safe_attr(message, "client_submit_time"))
        creation_time = _to_utc(_safe_attr(message, "creation_time"))

        hdr          = _parse_transport_headers(_safe_attr(message, "transport_headers"))
        sender_email = _extract_sender_email(hdr["from_header"])
        rcpts        = _parse_recipients(message)
        _fill_missing_recipients(rcpts, hdr)

        atts         = _parse_attachments(message)
        body_preview = _extract_body_preview(message)
        conv_id      = _safe_attr(message, "conversation_topic") or ""
        item_type    = _classify_item_type(message, folder_name)

        return {
            "source_file":      source_info["source_path"],
            "file_type":        source_info["file_type"],
            "file_format":      source_info["format"],
            "username":         source_info["username"],
            "file_size_bytes":  source_info["file_size"],
            "folder_path":      folder_path,
            "folder_name":      folder_name,
            "item_type":        item_type,
            "is_deleted":       is_deleted,
            "deletion_type":    deletion_type,
            "subject":          subject,
            "sender_name":      sender_name,
            "sender_email":     sender_email,
            "recipients_to":    "; ".join(rcpts["to_list"]),
            "recipients_cc":    "; ".join(rcpts["cc_list"]),
            "recipients_bcc":   "; ".join(rcpts["bcc_list"]),
            "delivery_time":    delivery_time,
            "submit_time":      submit_time,
            "creation_time":    creation_time,
            "has_attachment":   bool(atts),
            "attachment_count": len(atts),
            "attachments":      atts,
            "message_id":       hdr["message_id"],
            "x_originating_ip": hdr["x_originating_ip"],
            "received_servers": hdr["received_servers"],
            "conversation_id":  str(conv_id) if conv_id else "",
            "body_preview":     body_preview,
        }
    except Exception as exc:
        logger.debug("메시지 파싱 오류 [%s]: %s", folder_path, exc)
        return None


# ──────────────────────────────────────────
# 내부 — 헤더 파싱
# ──────────────────────────────────────────

def _parse_transport_headers(headers_str: str | None) -> dict:
    result: dict = {
        "message_id": "", "x_originating_ip": "", "received_servers": [],
        "from_header": "", "to_header": "", "cc_header": "", "bcc_header": "", "date_header": "",
    }
    if not headers_str:
        return result
    try:
        msg = email_lib.message_from_string(headers_str, policy=email_lib.policy.compat32)
        for mail_field, key in (
            ("Message-ID",       "message_id"),
            ("X-Originating-IP", "x_originating_ip"),
            ("From",             "from_header"),
            ("To",               "to_header"),
            ("Cc",               "cc_header"),
            ("Bcc",              "bcc_header"),
            ("Date",             "date_header"),
        ):
            result[key] = (msg.get(mail_field) or "").strip()

        result["received_servers"] = [
            parts[1]
            for rcv in (msg.get_all("Received") or [])
            if len(parts := rcv.strip().split("\n")[0].split()) > 1
            and parts[0].lower() == "from"
        ]
    except Exception as exc:
        logger.debug("헤더 파싱 오류: %s", exc)
    return result


def _extract_sender_email(from_header: str) -> str:
    if not from_header:
        return ""
    if "<" in from_header and ">" in from_header:
        return from_header.split("<")[1].split(">")[0].strip()
    return from_header.strip()


def _fill_missing_recipients(rcpts: dict, hdr: dict) -> None:
    if not rcpts["to_list"] and hdr["to_header"]:
        rcpts["to_list"] = [a.strip() for a in hdr["to_header"].split(",") if a.strip()]
    if not rcpts["cc_list"] and hdr["cc_header"]:
        rcpts["cc_list"] = [a.strip() for a in hdr["cc_header"].split(",") if a.strip()]


# ──────────────────────────────────────────
# 내부 — 수신자 파싱
# ──────────────────────────────────────────

def _parse_recipients(message) -> dict:
    to_list, cc_list, bcc_list = [], [], []
    try:
        for i in range(message.number_of_recipients):
            try:
                recipient = message.get_recipient(i)
                addr      = _format_address(recipient)
                rtype     = _recipient_type(recipient)
                if   rtype == 2: cc_list.append(addr)
                elif rtype == 3: bcc_list.append(addr)
                else:            to_list.append(addr)
            except Exception:
                continue
    except Exception as exc:
        logger.debug("수신자 파싱 오류: %s", exc)
    return {"to_list": to_list, "cc_list": cc_list, "bcc_list": bcc_list}


def _format_address(recipient) -> str:
    name  = (_safe_attr(recipient, "display_name")  or "").strip()
    email = (_safe_attr(recipient, "email_address") or "").strip()
    return f"{name} <{email}>" if name and email else email or name or ""


def _recipient_type(recipient) -> int:
    rtype = _safe_attr(recipient, "type")
    if isinstance(rtype, int):
        return rtype
    type_str = (_safe_attr(recipient, "type_string") or "").lower()
    if "cc"  in type_str: return 2
    if "bcc" in type_str: return 3
    return 1


# ──────────────────────────────────────────
# 내부 — 첨부파일 파싱
# ──────────────────────────────────────────

def _parse_attachments(message) -> list[dict]:
    attachments: list[dict] = []
    try:
        for i in range(message.number_of_attachments):
            try:
                att  = message.get_attachment(i)
                name = _get_attachment_name(att)
                size = _get_attachment_size(att)
                attachments.append({
                    "name": name,
                    "size": size,
                    "ext":  os.path.splitext(name)[1].lower() if name else "",
                })
            except Exception:
                continue
    except Exception as exc:
        logger.debug("첨부파일 파싱 오류: %s", exc)
    return attachments


def _get_attachment_name(att) -> str:
    for attr in ("name", "get_name"):
        try:
            val = getattr(att, attr)
            if callable(val): val = val()
            if val: return val.strip()
        except Exception:
            continue
    return ""


def _get_attachment_size(att) -> int:
    try:
        size_attr = getattr(att, "size", None)
        if size_attr is not None and not callable(size_attr):
            return int(size_attr)
        if hasattr(att, "get_size"):
            return int(att.get_size())
    except Exception:
        pass
    return 0


# ──────────────────────────────────────────
# 내부 — 본문·분류
# ──────────────────────────────────────────

def _extract_body_preview(message) -> str:
    body = _safe_attr(message, "plain_text_body")
    if body:
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        return body[:BODY_PREVIEW_LEN].replace("\r\n", " ").replace("\n", " ").strip()

    html = _safe_attr(message, "html_body")
    if html:
        if isinstance(html, bytes):
            html = html.decode("utf-8", errors="replace")
        plain = re.sub(r"<[^>]+>", " ", html)
        plain = re.sub(r"\s+",     " ", plain)
        return plain[:BODY_PREVIEW_LEN].strip()

    return ""


def _classify_item_type(message, folder_name: str) -> str:
    mc = ""
    for attr in ("message_class", "get_message_class"):
        try:
            val = getattr(message, attr, None)
            if callable(val): val = val()
            if val:
                mc = val.lower()
                break
        except Exception:
            pass

    if mc:
        for prefix, item_type in _ITEM_TYPE_MAP:
            if mc.startswith(prefix):
                return item_type

    fname = folder_name.lower()
    for keyword, item_type in _FOLDER_TYPE_HINTS:
        if keyword in fname:
            return item_type

    return "email"


# ──────────────────────────────────────────
# 내부 — 공통 유틸
# ──────────────────────────────────────────

def _safe_attr(obj, attr: str, default=None):
    try:
        return getattr(obj, attr, default)
    except Exception:
        return default


def _safe_call(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _to_utc(value) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _sort_key(entry: dict) -> float:
    for field in ("delivery_time", "submit_time", "creation_time"):
        ts = entry.get(field)
        if ts is not None and hasattr(ts, "timestamp"):
            return ts.timestamp()
    return 0.0