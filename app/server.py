import logging
import os
import threading
import time

from flask import Flask, jsonify, redirect, request

from .gmail_client import (
    build_auth_flow,
    exchange_code_for_tokens,
    get_gmail_service,
    list_unread_message_ids,
    load_stored_credentials,
    mark_message_as_read,
    send_reply_message,
)
from .gmail_client import fetch_message, parse_message_for_reply
from .openai_client import generate_reply_text


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("email-responder")

POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "180"))
FROM_EMAIL = os.environ.get("FROM_EMAIL", "").strip().lower()

app = Flask(__name__)


@app.get("/health")
def health_check():
    return jsonify({"status": "ok"})


@app.get("/oauth/start")
def oauth_start():
    redirect_uri = os.environ.get("GMAIL_REDIRECT_URL", "").strip()
    if not redirect_uri:
        return jsonify({"error": "GMAIL_REDIRECT_URL not set"}), 400

    flow = build_auth_flow(redirect_uri)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    return redirect(auth_url)


@app.get("/oauth/callback")
def oauth_callback():
    redirect_uri = os.environ.get("GMAIL_REDIRECT_URL", "").strip()
    if not redirect_uri:
        return jsonify({"error": "GMAIL_REDIRECT_URL not set"}), 400

    code = request.args.get("code")
    if not code:
        return jsonify({"error": "Missing code"}), 400

    exchange_code_for_tokens(code, redirect_uri)
    return "Gmail connected. You can close this tab."


def poll_once():
    if not load_stored_credentials():
        logger.info("No Gmail credentials yet; skipping poll.")
        return

    service = get_gmail_service()
    if service is None:
        logger.warning("Unable to build Gmail service; skipping poll.")
        return

    message_ids = list_unread_message_ids(service)
    if not message_ids:
        return

    for message_id in message_ids:
        message = fetch_message(service, message_id)
        if not message:
            continue

        parsed = parse_message_for_reply(message)
        if not parsed:
            continue

        from_email = parsed["from_email"].lower()
        if FROM_EMAIL and from_email == FROM_EMAIL:
            mark_message_as_read(service, message_id)
            continue

        reply_text = generate_reply_text(
            sender_name=parsed["from_name"],
            sender_email=parsed["from_email"],
            subject=parsed["subject"],
            original_body=parsed["body"],
        )
        if not reply_text:
            logger.warning("Assistant returned empty reply for %s", message_id)
            continue

        send_reply_message(
            service=service,
            thread_id=parsed["thread_id"],
            to_addr=parsed["reply_to"],
            subject=parsed["subject"],
            body=reply_text,
            in_reply_to=parsed["message_id"],
            references=parsed["references"],
        )
        mark_message_as_read(service, message_id)
        logger.info("Replied to message %s", message_id)


def poll_loop():
    while True:
        try:
            poll_once()
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Polling error: %s", exc)
        time.sleep(POLL_INTERVAL_SECONDS)


def start_background_polling():
    if os.environ.get("RUN_POLLING", "true").lower() != "true":
        logger.info("Polling disabled via RUN_POLLING.")
        return

    thread = threading.Thread(target=poll_loop, daemon=True)
    thread.start()
    logger.info("Started background polling thread.")


start_background_polling()

