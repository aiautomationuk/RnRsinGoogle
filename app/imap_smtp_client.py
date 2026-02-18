import imaplib
import os
import smtplib
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from email.mime.text import MIMEText
from email.utils import parseaddr


def _decode_header(value: str) -> str:
    if not value:
        return ""
    return str(make_header(decode_header(value)))


def _extract_body(message: Message) -> str:
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                payload = part.get_payload(decode=True)
                return (payload or b"").decode(part.get_content_charset() or "utf-8", errors="replace")
    payload = message.get_payload(decode=True)
    return (payload or b"").decode(message.get_content_charset() or "utf-8", errors="replace")


def _normalize_reply_subject(subject: str) -> str:
    subject = subject.strip()
    if not subject:
        return "Re: (no subject)"
    lowered = subject.lower()
    while lowered.startswith("re:"):
        subject = subject[3:].lstrip()
        lowered = subject.lower()
    return f"Re: {subject}"


def connect_imap():
    host = os.environ.get("IMAP_HOST", "").strip()
    port = int(os.environ.get("IMAP_PORT", "993"))
    username = os.environ.get("IMAP_USERNAME", "").strip()
    password = os.environ.get("IMAP_PASSWORD", "").strip()
    if not host or not username or not password:
        return None

    client = imaplib.IMAP4_SSL(host, port)
    client.login(username, password)
    return client


def list_unseen_uids(client, folder: str):
    client.select(folder)
    status, data = client.search(None, "UNSEEN")
    if status != "OK":
        return []
    return data[0].split()


def fetch_message_by_uid(client, uid: bytes):
    status, data = client.fetch(uid, "(RFC822)")
    if status != "OK" or not data:
        return None
    return message_from_bytes(data[0][1])


def mark_seen(client, uid: bytes):
    client.store(uid, "+FLAGS", "\\Seen")


def parse_imap_message(message: Message):
    from_header = _decode_header(message.get("From", ""))
    reply_to = _decode_header(message.get("Reply-To", "")) or from_header
    subject = _decode_header(message.get("Subject", "")) or "(no subject)"
    message_id = _decode_header(message.get("Message-ID", ""))
    references = _decode_header(message.get("References", ""))

    from_name, from_email = parseaddr(from_header)
    if not from_email:
        return None

    headers = []
    for key, value in message.items():
        headers.append({"name": key, "value": _decode_header(value)})

    return {
        "message_id": message_id,
        "references": references,
        "from_name": from_name or from_email,
        "from_email": from_email,
        "reply_to": parseaddr(reply_to)[1] or from_email,
        "subject": subject,
        "body": _extract_body(message),
        "headers": headers,
    }


def send_smtp_reply(to_addr: str, subject: str, body: str, in_reply_to: str, references: str, cc_addr: str | None):
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "465"))
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "").strip()
    from_addr = os.environ.get("SMTP_FROM", "").strip() or username
    if not host or not username or not password or not from_addr:
        raise ValueError("SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM are required.")

    mime = MIMEText(body)
    mime["To"] = to_addr
    if cc_addr:
        mime["Cc"] = cc_addr
    mime["Subject"] = _normalize_reply_subject(subject)
    if in_reply_to:
        mime["In-Reply-To"] = in_reply_to
    if references:
        mime["References"] = references
    mime["From"] = from_addr

    recipients = [to_addr] + ([cc_addr] if cc_addr else [])

    with smtplib.SMTP_SSL(host, port) as server:
        server.login(username, password)
        server.sendmail(from_addr, recipients, mime.as_string())
