import email as email_lib
import email.policy
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ─── 상수 ──────────────────────────────────────────────────────────────────────

# 폴더 이름 기반 삭제 항목 분류
_SOFT_DELETE_FOLDERS = {
    "deleted items",
    "deleted messages",
    "삭제된 항목",
    "trash",
    "bin",
}

_HARD_DELETE_FOLDERS = {
    "recoverable items",
    "purges",
    "deletions",
    "calendar logging",
    "audits",
    "복구 가능한 항목",
    "purge",
}

# 메시지 클래스 접두사 → item_type 분류
_ITEM_TYPE_MAP = [
    ("ipm.appointment",  "calendar"),
    ("ipm.contact",      "contact"),
    ("ipm.task",         "task"),
    ("ipm.stickynote",   "note"),
    ("ipm.activity",     "journal"),
    ("ipm.note",         "email"),
    ("ipm.",             "email"),   # 기타 IPM 항목도 이메일로 처리
]

# 한 폴더당 최대 파싱 메시지 수 (대용량 PST 보호)
MAX_MESSAGES_PER_FOLDER = 500

# 본문 미리보기 최대 길이
BODY_PREVIEW_LEN = 256


# ─── 타임스탬프 정규화 ──────────────────────────────────────────────────────────

def _to_utc(value) -> Optional[datetime]:
    """
    pypff가 반환하는 datetime을 UTC datetime으로 정규화합니다.
    pypff는 일반적으로 UTC datetime을 반환하지만 tzinfo가 없는 경우도 있습니다.
    """
    if value is None:
        return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# ─── 헤더 파싱 ─────────────────────────────────────────────────────────────────

def _parse_transport_headers(headers_str: Optional[str]) -> dict:
    result: dict = {
        "message_id": "",
        "x_originating_ip": "",
        "received_servers": [],
        "from_header": "",
        "to_header": "",
        "cc_header": "",
        "bcc_header": "",
        "date_header": "",
    }
    if not headers_str:
        return result
    try:
        msg = email_lib.message_from_string(headers_str, policy=email_lib.policy.compat32)
        result["message_id"]       = (msg.get("Message-ID") or "").strip()
        result["x_originating_ip"] = (msg.get("X-Originating-IP") or "").strip()
        result["from_header"]      = (msg.get("From") or "").strip()
        result["to_header"]        = (msg.get("To") or "").strip()
        result["cc_header"]        = (msg.get("Cc") or "").strip()
        result["bcc_header"]       = (msg.get("Bcc") or "").strip()
        result["date_header"]      = (msg.get("Date") or "").strip()
        # Received 헤더 여러 개 수집 → 라우팅 경로 재구성
        received_servers = []
        for rcv in msg.get_all("Received") or []:
            # "from mail.example.com by ..." 에서 발신 서버만 추출
            rcv_line = rcv.strip().split("\n")[0]  # 멀티라인 헤더의 첫 줄
            if rcv_line.lower().startswith("from "):
                server = rcv_line.split()[1] if len(rcv_line.split()) > 1 else ""
                if server:
                    received_servers.append(server)
        result["received_servers"] = received_servers
    except Exception as exc:
        logger.debug("헤더 파싱 오류: %s", exc)
    return result


# ─── 수신자 파싱 ───────────────────────────────────────────────────────────────

def _parse_recipients(message) -> dict:
    """
    pypff message 객체에서 수신자 목록을 파싱합니다.

    pypff 수신자 타입 값:
      0 = 알 수 없음 / 발신자
      1 = To (MAPI_TO)
      2 = CC (MAPI_CC)
      3 = BCC (MAPI_BCC)

    반환:
      to_list  : To 수신자 문자열 목록
      cc_list  : CC 수신자 문자열 목록
      bcc_list : BCC 수신자 문자열 목록
    """
    to_list, cc_list, bcc_list = [], [], []
    try:
        count = message.number_of_recipients
        for i in range(count):
            try:
                recipient = message.get_recipient(i)
                name  = (recipient.display_name or "").strip()
                email = (recipient.email_address or "").strip()
                addr  = f"{name} <{email}>" if name and email else (email or name or "")
                rtype = getattr(recipient, "type", None)
                # recipient.type 은 정수; 일부 pypff 빌드는 None을 반환
                if rtype is None:
                    # type_string 프로퍼티로 시도
                    type_str = getattr(recipient, "type_string", "") or ""
                    rtype_str = type_str.lower()
                    if "cc" in rtype_str:
                        rtype = 2
                    elif "bcc" in rtype_str:
                        rtype = 3
                    else:
                        rtype = 1  # 기본값 To
                if rtype == 2:
                    cc_list.append(addr)
                elif rtype == 3:
                    bcc_list.append(addr)
                else:
                    to_list.append(addr)
            except Exception:
                continue
    except Exception as exc:
        logger.debug("수신자 파싱 오류: %s", exc)
    return {"to_list": to_list, "cc_list": cc_list, "bcc_list": bcc_list}


# ─── 첨부파일 파싱 ─────────────────────────────────────────────────────────────

def _parse_attachments(message) -> list:
    """
    첨부파일 메타데이터를 추출합니다 (내용은 읽지 않음 - 성능 보호).

    반환 항목 필드:
      name : 첨부파일 이름
      size : 바이트 크기 (없으면 0)
      ext  : 확장자 소문자 (예: ".pdf")
    """
    attachments = []
    try:
        count = message.number_of_attachments
        for i in range(count):
            try:
                att = message.get_attachment(i)
                # 파일명 우선순위: long filename → short name → ""
                name = ""
                for attr in ("name", "get_name"):
                    try:
                        val = getattr(att, attr)
                        if callable(val):
                            val = val()
                        if val:
                            name = val.strip()
                            break
                    except Exception:
                        continue
                size = 0
                try:
                    size_attr = getattr(att, "size", None)
                    if size_attr is not None and not callable(size_attr):
                        size = int(size_attr)
                    elif hasattr(att, "get_size"):
                        size = int(att.get_size())
                except Exception:
                    pass
                attachments.append({
                    "name": name,
                    "size": size,
                    "ext": os.path.splitext(name)[1].lower() if name else "",
                })
            except Exception:
                continue
    except Exception as exc:
        logger.debug("첨부파일 파싱 오류: %s", exc)
    return attachments


# ─── 본문 추출 ─────────────────────────────────────────────────────────────────

def _extract_body_preview(message) -> str:
    """
    메시지 본문에서 첫 BODY_PREVIEW_LEN 글자를 추출합니다.
    plain_text_body 우선, 없으면 html_body에서 태그 제거 후 사용.
    """
    try:
        body = message.plain_text_body
        if body:
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            return body[:BODY_PREVIEW_LEN].replace("\r\n", " ").replace("\n", " ").strip()
    except Exception:
        pass
    try:
        html = message.html_body
        if html:
            if isinstance(html, bytes):
                html = html.decode("utf-8", errors="replace")
            # 단순 태그 제거 (정규식 없이)
            import re
            plain = re.sub(r"<[^>]+>", " ", html)
            plain = re.sub(r"\s+", " ", plain)
            return plain[:BODY_PREVIEW_LEN].strip()
    except Exception:
        pass
    return ""


# ─── 아이템 타입 분류 ──────────────────────────────────────────────────────────

def _classify_item_type(message, folder_name: str) -> str:
    """
    메시지 클래스(PR_MESSAGE_CLASS) 또는 폴더 이름으로 항목 종류를 분류합니다.
    """
    # pypff.message.message_class 또는 get_message_class() 시도
    mc = ""
    for attr in ("message_class", "get_message_class"):
        try:
            val = getattr(message, attr, None)
            if callable(val):
                val = val()
            if val:
                mc = val.lower()
                break
        except Exception:
            pass

    if mc:
        for prefix, item_type in _ITEM_TYPE_MAP:
            if mc.startswith(prefix):
                return item_type

    # 폴더 이름 기반 휴리스틱 분류
    fname = folder_name.lower()
    if "calendar" in fname or "칼렌더" in fname or "일정" in fname:
        return "calendar"
    if "contact" in fname or "연락처" in fname:
        return "contact"
    if "task" in fname or "작업" in fname:
        return "task"
    if "note" in fname or "메모" in fname:
        return "note"
    return "email"


# ─── 단일 메시지 파싱 ──────────────────────────────────────────────────────────

def _parse_single_message(
    message,
    folder_path: str,
    folder_name: str,
    source_info: dict,
    is_deleted: bool,
    deletion_type: Optional[str],
) -> Optional[dict]:
    """
    pypff.message 객체 하나를 포렌식 항목 딕셔너리로 변환합니다.

    오류 발생 시 None을 반환합니다 (부분 손상 메시지 skip).
    """
    try:
        # ── 기본 속성 ────────────────────────────────────────────────────────────
        subject = ""
        try:
            subject = message.subject or ""
        except Exception:
            pass

        sender_name = ""
        try:
            sender_name = message.sender_name or ""
        except Exception:
            pass

        # ── 타임스탬프 ───────────────────────────────────────────────────────────
        delivery_time = None
        submit_time = None
        creation_time = None
        try:
            delivery_time = _to_utc(message.delivery_time)
        except Exception:
            pass
        try:
            submit_time = _to_utc(message.client_submit_time)
        except Exception:
            pass
        try:
            creation_time = _to_utc(message.creation_time)
        except Exception:
            pass

        # ── Transport Headers ────────────────────────────────────────────────────
        headers_str = None
        try:
            headers_str = message.transport_headers
        except Exception:
            pass
        hdr = _parse_transport_headers(headers_str)

        # sender_email: 헤더의 From > pypff sender_name 순서
        sender_email = ""
        if hdr["from_header"]:
            # "Display Name <addr@example.com>" 에서 이메일 추출
            fh = hdr["from_header"]
            if "<" in fh and ">" in fh:
                sender_email = fh.split("<")[1].split(">")[0].strip()
            else:
                sender_email = fh.strip()

        # ── 수신자 ──────────────────────────────────────────────────────────────
        rcpts = _parse_recipients(message)

        # To 목록이 비어있고 헤더의 To가 있으면 보완
        if not rcpts["to_list"] and hdr["to_header"]:
            rcpts["to_list"] = [a.strip() for a in hdr["to_header"].split(",") if a.strip()]
        if not rcpts["cc_list"] and hdr["cc_header"]:
            rcpts["cc_list"] = [a.strip() for a in hdr["cc_header"].split(",") if a.strip()]

        # ── 첨부파일 ─────────────────────────────────────────────────────────────
        atts = _parse_attachments(message)
        has_att = len(atts) > 0

        # ── 본문 미리보기 ────────────────────────────────────────────────────────
        body_preview = _extract_body_preview(message)

        # ── Conversation Index (스레드 식별) ─────────────────────────────────────
        # Conversation-Index는 22바이트 헤더 + 5바이트 * N 블록
        # 첫 22바이트 중 바이트 5-21(GUID 포함)이 스레드를 고유하게 식별
        conv_id = ""
        try:
            ci = message.conversation_topic
            if ci:
                conv_id = str(ci)
        except Exception:
            pass

        # ── 항목 타입 분류 ──────────────────────────────────────────────────────
        item_type = _classify_item_type(message, folder_name)

        return {
            # 출처
            "source_file":       source_info["source_path"],
            "file_type":         source_info["file_type"],
            "file_format":       source_info["format"],
            "username":          source_info["username"],
            "file_size_bytes":   source_info["file_size"],
            # 위치
            "folder_path":       folder_path,
            "folder_name":       folder_name,
            # 분류
            "item_type":         item_type,
            "is_deleted":        is_deleted,
            "deletion_type":     deletion_type,
            # 이메일 필드
            "subject":           subject,
            "sender_name":       sender_name,
            "sender_email":      sender_email,
            "recipients_to":     "; ".join(rcpts["to_list"]),
            "recipients_cc":     "; ".join(rcpts["cc_list"]),
            "recipients_bcc":    "; ".join(rcpts["bcc_list"]),
            # 타임스탬프
            "delivery_time":     delivery_time,
            "submit_time":       submit_time,
            "creation_time":     creation_time,
            # 첨부파일
            "has_attachment":    has_att,
            "attachment_count":  len(atts),
            "attachments":       atts,
            # 헤더 정보
            "message_id":        hdr["message_id"],
            "x_originating_ip":  hdr["x_originating_ip"],
            "received_servers":  hdr["received_servers"],
            # 기타
            "conversation_id":   conv_id,
            "body_preview":      body_preview,
        }
    except Exception as exc:
        logger.debug("메시지 파싱 오류 [%s/%s]: %s", folder_path, subject if "subject" in dir() else "?", exc)
        return None


# ─── 폴더 트리 순회 ────────────────────────────────────────────────────────────

def _is_deleted_folder(folder_name: str) -> tuple:
    """
    폴더 이름으로 삭제 항목 여부와 삭제 종류를 판단합니다.

    반환: (is_deleted: bool, deletion_type: str|None)
    """
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
    results: list,
    parent_deleted: bool = False,
    parent_deletion_type: Optional[str] = None,
    depth: int = 0,
    max_depth: int = 30,
) -> None:
    """
    pypff 폴더 객체를 재귀 순회하며 모든 메시지를 파싱합니다.

    depth 제한으로 순환 참조가 있는 손상 파일 처리 시 무한 재귀를 방지합니다.
    """
    if depth > max_depth:
        logger.debug("최대 폴더 깊이 초과: %s", folder_path)
        return

    try:
        folder_name = folder.name or folder_path.rsplit("/", 1)[-1] or "Unknown"
    except Exception:
        folder_name = "Unknown"

    # 삭제 상태 상속 (부모 폴더가 삭제 폴더이면 모든 하위 항목도 deleted)
    folder_deleted, folder_deletion_type = _is_deleted_folder(folder_name)
    is_deleted = parent_deleted or folder_deleted
    deletion_type = parent_deletion_type or folder_deletion_type

    # ── 하위 메시지 처리 ────────────────────────────────────────────────────────
    try:
        msg_count = folder.number_of_sub_messages
    except Exception:
        msg_count = 0

    parsed_count = 0
    for i in range(min(msg_count, MAX_MESSAGES_PER_FOLDER)):
        try:
            msg = folder.get_sub_message(i)
            if msg is None:
                continue
            entry = _parse_single_message(
                msg, folder_path, folder_name, source_info, is_deleted, deletion_type
            )
            if entry:
                results.append(entry)
                parsed_count += 1
        except Exception as exc:
            logger.debug("메시지 #%d 오류 [%s]: %s", i, folder_path, exc)
            continue

    if msg_count > MAX_MESSAGES_PER_FOLDER:
        logger.info(
            "폴더 '%s': %d/%d 메시지만 파싱 (MAX_MESSAGES_PER_FOLDER 제한)",
            folder_path, parsed_count, msg_count
        )

    # ── 하위 폴더 재귀 처리 ─────────────────────────────────────────────────────
    try:
        sub_folder_count = folder.number_of_sub_folders
    except Exception:
        sub_folder_count = 0

    for i in range(sub_folder_count):
        try:
            sub = folder.get_sub_folder(i)
            if sub is None:
                continue
            try:
                sub_name = sub.name or f"folder_{i}"
            except Exception:
                sub_name = f"folder_{i}"
            sub_path = f"{folder_path}/{sub_name}"
            _walk_folder(
                sub, sub_path, source_info, results,
                is_deleted, deletion_type, depth + 1, max_depth
            )
        except Exception as exc:
            logger.debug("하위폴더 #%d 오류 [%s]: %s", i, folder_path, exc)
            continue


# ─── PST/OST 단일 파일 파싱 ────────────────────────────────────────────────────

def _parse_pff_file(raw_item: dict) -> list:
    """
    단일 PST/OST 파일을 pypff로 완전 파싱합니다.

    처리 순서:
      1. pypff.file() 생성
      2. open_file_object() 또는 open() 호출
      3. 루트 폴더부터 재귀 순회 (일반 폴더 + Recoverable Items)
      4. Orphan 아이템 처리 (libpff 복구 삭제 항목)
      5. 파일 닫기
    """
    try:
        import pypff
    except ImportError:
        logger.error(
            "pypff를 찾을 수 없습니다. 설치 필요:\n"
            "  Windows: pip install libpff-python\n"
            "  Linux:   pip install libpff-python 또는 소스 빌드"
        )
        return []

    results: list = []
    pff_file = None

    try:
        pff_file = pypff.file()

        # 파일 열기: 스트리밍 파일 객체 우선, 없으면 직접 경로 열기
        file_obj = raw_item.get("file_object")
        local_path = raw_item.get("_local_path")

        if file_obj is not None:
            pff_file.open_file_object(file_obj)
        elif local_path and os.path.isfile(local_path):
            pff_file.open(local_path)
        else:
            logger.warning("PST/OST: 열 수 있는 파일 소스가 없습니다: %s", raw_item.get("source_path"))
            return []

        logger.info(
            "PST/OST 파싱 시작: %s [%s %s %.1f MB]",
            raw_item["source_path"],
            raw_item["file_type"],
            raw_item["format"],
            raw_item["file_size"] / (1024 * 1024),
        )

        source_info = raw_item  # 각 메시지 항목에 출처 정보 포함용

        # ── 1. 루트 폴더부터 정상 트리 순회 ────────────────────────────────────
        try:
            root = pff_file.get_root_folder()
            if root:
                _walk_folder(root, "/", source_info, results)
        except Exception as exc:
            logger.warning("루트 폴더 접근 오류 [%s]: %s", raw_item["source_path"], exc)

        # ── 2. Orphan 아이템 처리 (libpff 복구 삭제 항목) ───────────────────────
        # libpff는 NDB 레이어에서 참조 없는 노드를 복구하여 orphan_items에 제공합니다.
        # 이는 사용자가 Recoverable Items도 비워서 Outlook에서는 보이지 않는 항목들입니다.
        try:
            orphan_count = pff_file.get_number_of_orphan_items()
            recovered = 0
            for i in range(orphan_count):
                try:
                    item = pff_file.get_orphan_item(i)
                    if item is None:
                        continue
                    # orphan_item이 message 타입인지 확인
                    if not isinstance(item, pypff.message):
                        continue
                    entry = _parse_single_message(
                        item, "/Orphan", "Orphan", source_info,
                        is_deleted=True, deletion_type="orphan"
                    )
                    if entry:
                        results.append(entry)
                        recovered += 1
                except Exception:
                    continue
            if recovered:
                logger.info("Orphan 복구 항목: %d개", recovered)
        except Exception as exc:
            logger.debug("Orphan 처리 오류: %s", exc)

        logger.info(
            "PST/OST 파싱 완료: %s → %d개 항목",
            raw_item["source_path"], len(results)
        )

    except Exception as exc:
        logger.warning("PST/OST 파일 파싱 실패 [%s]: %s", raw_item.get("source_path"), exc)
    finally:
        if pff_file:
            try:
                pff_file.close()
            except Exception:
                pass

    return results


# ─── 정렬 키 ───────────────────────────────────────────────────────────────────

def _sort_key(entry: dict) -> float:
    """최근 수신/발신 이메일이 상단에 오도록 내림차순 정렬 키."""
    ts = entry.get("delivery_time") or entry.get("submit_time") or entry.get("creation_time")
    if ts and hasattr(ts, "timestamp"):
        return ts.timestamp()
    return 0.0


# ─── 공개 인터페이스 ───────────────────────────────────────────────────────────

def parse(raw_items: list) -> list:
    """
    ost_pst_collector.collect_from_image()의 반환값을 받아
    모든 PST/OST 파일에서 메시지 항목을 추출한 정제된 목록을 반환합니다.

    pypff가 설치되지 않은 경우 빈 목록과 오류 로그를 반환합니다.
    설치 명령어: pip install libpff-python
    """
    if not raw_items:
        return []

    all_entries: list = []
    for raw_item in raw_items:
        entries = _parse_pff_file(raw_item)
        all_entries.extend(entries)

    # delivery_time 내림차순 정렬 (가장 최근 이메일 최상단)
    all_entries.sort(key=_sort_key, reverse=True)

    logger.info(
        "OST/PST 전체 파싱 완료: 파일 %d개 → 총 %d개 항목 (삭제 포함 %d개)",
        len(raw_items),
        len(all_entries),
        sum(1 for e in all_entries if e.get("is_deleted")),
    )
    return all_entries