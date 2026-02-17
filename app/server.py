import logging
import os
import threading
import time

from flask import Flask, jsonify, redirect, request, session as flask_session
from google.auth.transport.requests import Request
from google.oauth2 import id_token

from .db import get_session, init_db
from .gmail_client import (
    build_gmail_auth_flow,
    credentials_to_dict,
    exchange_code_for_tokens,
    fetch_message,
    get_gmail_service,
    is_likely_bulk,
    list_unread_message_ids,
    mark_message_as_read,
    parse_message_for_reply,
    send_reply_message,
)
from .models import GmailToken, User
from .oauth_client import build_oauth_flow
from .openai_client import generate_reply_text


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("email-responder")

POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "180"))
LOGIN_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")


def _google_oauth_client_id():
    return (
        os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "").strip()
        or os.environ.get("GMAIL_CLIENT_ID", "").strip()
    )

init_db()


@app.get("/health")
def health_check():
    return jsonify({"status": "ok"})


@app.get("/")
def root():
    return jsonify({"status": "ok"})


def _current_user(session_db):
    user_id = flask_session.get("user_id")
    if not user_id:
        return None
    return session_db.get(User, user_id)


@app.get("/auth/google/start")
def google_login_start():
    redirect_uri = os.environ.get("GOOGLE_OAUTH_REDIRECT_URL", "").strip()
    if not redirect_uri:
        return jsonify({"error": "GOOGLE_OAUTH_REDIRECT_URL not set"}), 400

    flow = build_oauth_flow(LOGIN_SCOPES, redirect_uri)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    flask_session["login_state"] = state
    return redirect(auth_url)


@app.get("/auth/google/callback")
def google_login_callback():
    redirect_uri = os.environ.get("GOOGLE_OAUTH_REDIRECT_URL", "").strip()
    if not redirect_uri:
        return jsonify({"error": "GOOGLE_OAUTH_REDIRECT_URL not set"}), 400

    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return jsonify({"error": "Missing code"}), 400
    if state and flask_session.get("login_state") and state != flask_session.get("login_state"):
        return jsonify({"error": "Invalid state"}), 400

    flow = build_oauth_flow(LOGIN_SCOPES, redirect_uri)
    flow.fetch_token(code=code)
    client_id = _google_oauth_client_id()
    if not client_id:
        return jsonify({"error": "GOOGLE_OAUTH_CLIENT_ID not set"}), 400
    token_info = id_token.verify_oauth2_token(
        flow.credentials.id_token,
        Request(),
        audience=client_id,
    )
    google_sub = token_info.get("sub")
    email = token_info.get("email")
    if not google_sub or not email:
        return jsonify({"error": "Unable to read user identity"}), 400

    with get_session() as session_db:
        user = session_db.query(User).filter_by(google_sub=google_sub).one_or_none()
        if not user:
            user = User(google_sub=google_sub, email=email)
            session_db.add(user)
            session_db.commit()
        flask_session["user_id"] = user.id

    return jsonify({"status": "logged_in", "email": email})


@app.get("/logout")
def logout():
    flask_session.clear()
    return jsonify({"status": "logged_out"})


@app.get("/oauth/start")
def oauth_start():
    return redirect("/gmail/connect/start")


@app.get("/oauth/callback")
def oauth_callback():
    return redirect("/gmail/connect/callback")


@app.get("/gmail/connect/start")
def gmail_connect_start():
    redirect_uri = os.environ.get("GMAIL_REDIRECT_URL", "").strip()
    if not redirect_uri:
        return jsonify({"error": "GMAIL_REDIRECT_URL not set"}), 400

    with get_session() as session_db:
        user = _current_user(session_db)
        if not user:
            return jsonify({"error": "Login required"}), 401

    flow = build_gmail_auth_flow(redirect_uri)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    flask_session["gmail_state"] = state
    return redirect(auth_url)


@app.get("/gmail/connect/callback")
def gmail_connect_callback():
    redirect_uri = os.environ.get("GMAIL_REDIRECT_URL", "").strip()
    if not redirect_uri:
        return jsonify({"error": "GMAIL_REDIRECT_URL not set"}), 400

    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return jsonify({"error": "Missing code"}), 400
    if state and flask_session.get("gmail_state") and state != flask_session.get("gmail_state"):
        return jsonify({"error": "Invalid state"}), 400

    with get_session() as session_db:
        user = _current_user(session_db)
        if not user:
            return jsonify({"error": "Login required"}), 401

        credentials = exchange_code_for_tokens(code, redirect_uri)
        token_data = credentials_to_dict(credentials)
        existing = session_db.query(GmailToken).filter_by(user_id=user.id).one_or_none()
        if existing:
            existing.token_json = token_data
        else:
            session_db.add(GmailToken(user_id=user.id, token_json=token_data))
        session_db.commit()

    return "Gmail connected. You can close this tab."


def poll_once():
    with get_session() as session_db:
        tokens = session_db.query(GmailToken).join(User).all()
        if not tokens:
            logger.info("No Gmail credentials yet; skipping poll.")
            return

        for token in tokens:
            service, updated = get_gmail_service(token.token_json)
            if service is None:
                logger.warning("Unable to build Gmail service; skipping user %s", token.user.email)
                continue

            if updated:
                token.token_json = updated
                session_db.commit()

            message_ids = list_unread_message_ids(service)
            if not message_ids:
                continue

            for message_id in message_ids:
                message = fetch_message(service, message_id)
                if not message:
                    continue

                parsed = parse_message_for_reply(message)
                if not parsed:
                    continue

                from_email = parsed["from_email"].lower()
                if from_email == token.user.email.lower():
                    mark_message_as_read(service, message_id)
                    continue

                if is_likely_bulk(parsed["headers"], parsed["subject"], parsed["body"], from_email):
                    logger.info("Skipping likely bulk email from %s", from_email)
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)

