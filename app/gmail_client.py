import base64
import os
from email.mime.text import MIMEText
from email.utils import parseaddr

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from .oauth_client import build_oauth_flow

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")


def build_gmail_auth_flow(redirect_uri: str):
    return build_oauth_flow(GMAIL_SCOPES, redirect_uri)


def credentials_to_dict(credentials: Credentials) -> dict:
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }


def credentials_from_dict(data: dict):
    return Credentials(**data)


def exchange_code_for_tokens(code: str, redirect_uri: str):
    flow = build_gmail_auth_flow(redirect_uri)
    flow.fetch_token(code=code)
    return flow.credentials


def get_gmail_service(credentials_dict: dict):
    if not credentials_dict:
        return None, None
    credentials = credentials_from_dict(credentials_dict)
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
        return build("gmail", "v1", credentials=credentials), credentials_to_dict(credentials)

    return build("gmail", "v1", credentials=credentials), None


def list_unread_message_ids(service, max_results: int = 10):
    response = (
        service.users()
        .messages()
        .list(userId="me", q="is:unread in:inbox", maxResults=max_results)
        .execute()
    )
    messages = response.get("messages", [])
    return [msg["id"] for msg in messages]


def fetch_message(service, message_id: str):
    return (
        service.users()
        .messages()
        .get(userId="me", id=message_id, format="full")
        .execute()
    )


def _get_header(headers, name):
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""


def _extract_body(payload):
    if "parts" in payload:
        for part in payload["parts"]:
            if part.get("mimeType") == "text/plain":
                data = part.get("body", {}).get("data", "")
                return _decode_body(data)
        for part in payload["parts"]:
            if "parts" in part:
                nested = _extract_body(part)
                if nested:
                    return nested
    data = payload.get("body", {}).get("data", "")
    return _decode_body(data)


def _decode_body(data):
    if not data:
        return ""
    return base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="replace")


def parse_message_for_reply(message):
    payload = message.get("payload", {})
    headers = payload.get("headers", [])

    from_header = _get_header(headers, "From")
    reply_to = _get_header(headers, "Reply-To") or from_header
    subject = _get_header(headers, "Subject") or "(no subject)"
    message_id = _get_header(headers, "Message-ID")
    references = _get_header(headers, "References")

    from_name, from_email = parseaddr(from_header)
    if not from_email:
        return None

    return {
        "thread_id": message.get("threadId"),
        "message_id": message_id,
        "references": references,
        "from_name": from_name or from_email,
        "from_email": from_email,
        "reply_to": parseaddr(reply_to)[1] or from_email,
        "subject": subject,
        "body": _extract_body(payload),
        "headers": headers,
    }


def is_likely_bulk(headers, subject: str, body: str, from_email: str) -> bool:
    subject_lower = (subject or "").lower()
    body_lower = (body or "").lower()
    from_lower = (from_email or "").lower()

    header_map = {header.get("name", "").lower(): header.get("value", "") for header in headers}
    precedence = header_map.get("precedence", "").lower()
    auto_submitted = header_map.get("auto-submitted", "").lower()
    list_unsubscribe = header_map.get("list-unsubscribe", "")
    list_id = header_map.get("list-id", "")
    auto_response = header_map.get("x-auto-response-suppress", "")

    if precedence in {"bulk", "junk", "list"}:
        return True
    if auto_submitted and auto_submitted != "no":
        return True
    if list_unsubscribe or list_id or auto_response:
        return True

    if any(token in from_lower for token in ["no-reply", "noreply", "mailer-daemon", "postmaster"]):
        return True

    subject_tokens = [
        "unsubscribe",
        "sale",
        "promotion",
        "newsletter",
        "deal",
        "offer",
        "discount",
        "webinar",
        "digest",
        "trial",
    ]
    if any(token in subject_lower for token in subject_tokens):
        return True

    body_tokens = ["unsubscribe", "view in browser", "manage preferences"]
    if any(token in body_lower for token in body_tokens):
        return True

    return False


def send_reply_message(
    service,
    thread_id: str,
    to_addr: str,
    subject: str,
    body: str,
    in_reply_to: str,
    references: str,
    cc_addr: str | None = None,
):
    mime = MIMEText(body)
    mime["To"] = to_addr
    if cc_addr:
        mime["Cc"] = cc_addr
    mime["Subject"] = f"Re: {subject}"
    if in_reply_to:
        mime["In-Reply-To"] = in_reply_to
    if references:
        mime["References"] = references

    raw_message = base64.urlsafe_b64encode(mime.as_bytes()).decode("utf-8")
    message = {"raw": raw_message, "threadId": thread_id}
    return service.users().messages().send(userId="me", body=message).execute()


def mark_message_as_read(service, message_id: str):
    body = {"removeLabelIds": ["UNREAD"]}
    return service.users().messages().modify(userId="me", id=message_id, body=body).execute()

