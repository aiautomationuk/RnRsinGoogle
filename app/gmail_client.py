import base64
import json
import os
from email.mime.text import MIMEText
from email.utils import parseaddr

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
TOKEN_STORE_PATH = os.environ.get("TOKEN_STORE_PATH", "/var/data/token_store.json")


def _client_config():
    client_id = os.environ.get("GMAIL_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GMAIL_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        raise ValueError("GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET must be set.")

    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }


def build_auth_flow(redirect_uri: str) -> Flow:
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES)
    flow.redirect_uri = redirect_uri
    return flow


def _credentials_to_dict(credentials: Credentials) -> dict:
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }


def load_stored_credentials():
    if not os.path.exists(TOKEN_STORE_PATH):
        return None
    with open(TOKEN_STORE_PATH, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return Credentials(**data)


def save_credentials(credentials: Credentials):
    os.makedirs(os.path.dirname(TOKEN_STORE_PATH), exist_ok=True)
    with open(TOKEN_STORE_PATH, "w", encoding="utf-8") as handle:
        json.dump(_credentials_to_dict(credentials), handle)


def exchange_code_for_tokens(code: str, redirect_uri: str):
    flow = build_auth_flow(redirect_uri)
    flow.fetch_token(code=code)
    save_credentials(flow.credentials)


def get_gmail_service():
    credentials = load_stored_credentials()
    if not credentials:
        return None

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
        save_credentials(credentials)

    return build("gmail", "v1", credentials=credentials)


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
):
    mime = MIMEText(body)
    mime["To"] = to_addr
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

