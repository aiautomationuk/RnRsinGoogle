import logging
import os
import threading
import time

from flask import Flask, jsonify, request
from sqlalchemy.exc import IntegrityError

from .db import get_session, init_db
from .imap_smtp_client import (
    connect_imap,
    fetch_message_by_uid,
    is_likely_bulk,
    list_unseen_uids,
    mark_seen,
    parse_imap_message,
    send_smtp_reply,
)
from .models import ImapCredential, ProcessedImapMessage
from .openai_client import classify_importance, generate_reply_text


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("email-responder")

POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "180"))
EMERGENCY_CC_EMAIL = os.environ.get("EMERGENCY_CC_EMAIL", "").strip()
EMERGENCY_CC_LEVEL = os.environ.get("EMERGENCY_CC_LEVEL", "important").strip().lower()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")


def _seed_imap_from_env():
    """If no IMAP accounts are in the database, create one from environment variables."""
    imap_host = os.environ.get("IMAP_HOST", "").strip()
    imap_username = os.environ.get("IMAP_USERNAME", "").strip()
    imap_password = os.environ.get("IMAP_PASSWORD", "").strip()
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_username = os.environ.get("SMTP_USERNAME", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    smtp_from = os.environ.get("SMTP_FROM", "").strip()

    if not all([imap_host, imap_username, imap_password, smtp_host, smtp_username, smtp_password, smtp_from]):
        return  # env vars not set — skip

    try:
        with get_session() as session_db:
            exists = session_db.query(ImapCredential).filter_by(imap_username=imap_username).one_or_none()
            if exists:
                return  # already seeded
            session_db.add(ImapCredential(
                imap_host=imap_host,
                imap_port=int(os.environ.get("IMAP_PORT", "993")),
                imap_username=imap_username,
                imap_password=imap_password,
                imap_folder=os.environ.get("IMAP_FOLDER", "INBOX"),
                smtp_host=smtp_host,
                smtp_port=int(os.environ.get("SMTP_PORT", "465")),
                smtp_username=smtp_username,
                smtp_password=smtp_password,
                smtp_from=smtp_from,
                openai_assistant_id=os.environ.get("OPENAI_ASSISTANT_ID_OVERRIDE") or None,
            ))
            session_db.commit()
            logger.info("Seeded IMAP account from environment variables: %s", imap_username)
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Failed to seed IMAP account from env: %s", exc)


init_db()
_seed_imap_from_env()


def _check_admin_secret():
    """Return a 401 response if ADMIN_SECRET is set and the request doesn't supply it."""
    secret = os.environ.get("ADMIN_SECRET", "").strip()
    if not secret:
        return None  # no secret configured — open access (dev mode)
    provided = (
        request.headers.get("X-Admin-Secret", "")
        or request.args.get("secret", "")
    )
    if provided != secret:
        return jsonify({"error": "Unauthorized"}), 401
    return None


@app.get("/health")
def health_check():
    return jsonify({"status": "ok"})


@app.get("/")
def root():
    return jsonify({"status": "ok"})


@app.post("/imap/connect")
def imap_connect():
    err = _check_admin_secret()
    if err:
        return err

    data = request.get_json() or {}
    required = ["imap_host", "imap_username", "imap_password", "smtp_host", "smtp_username", "smtp_password", "smtp_from"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"{field} is required"}), 400

    with get_session() as session_db:
        existing = (
            session_db.query(ImapCredential)
            .filter_by(imap_username=data["imap_username"])
            .one_or_none()
        )
        if existing:
            existing.imap_host = data["imap_host"]
            existing.imap_port = int(data.get("imap_port", 993))
            existing.imap_password = data["imap_password"]
            existing.imap_folder = data.get("imap_folder", "INBOX")
            existing.smtp_host = data["smtp_host"]
            existing.smtp_port = int(data.get("smtp_port", 2525))
            existing.smtp_username = data["smtp_username"]
            existing.smtp_password = data["smtp_password"]
            existing.smtp_from = data["smtp_from"]
            existing.openai_assistant_id = data.get("openai_assistant_id") or None
        else:
            session_db.add(ImapCredential(
                imap_host=data["imap_host"],
                imap_port=int(data.get("imap_port", 993)),
                imap_username=data["imap_username"],
                imap_password=data["imap_password"],
                imap_folder=data.get("imap_folder", "INBOX"),
                smtp_host=data["smtp_host"],
                smtp_port=int(data.get("smtp_port", 2525)),
                smtp_username=data["smtp_username"],
                smtp_password=data["smtp_password"],
                smtp_from=data["smtp_from"],
                openai_assistant_id=data.get("openai_assistant_id") or None,
            ))
        session_db.commit()

    return jsonify({"status": "imap_connected"})


@app.get("/imap/accounts")
def imap_accounts():
    err = _check_admin_secret()
    if err:
        return err

    with get_session() as session_db:
        creds = session_db.query(ImapCredential).all()
        return jsonify([
            {
                "id": c.id,
                "imap_username": c.imap_username,
                "smtp_from": c.smtp_from,
                "openai_assistant_id": c.openai_assistant_id,
            }
            for c in creds
        ])


@app.delete("/imap/account/<int:account_id>")
def imap_delete_account(account_id):
    err = _check_admin_secret()
    if err:
        return err

    with get_session() as session_db:
        cred = session_db.query(ImapCredential).filter_by(id=account_id).one_or_none()
        if not cred:
            return jsonify({"error": "Not found"}), 404
        session_db.delete(cred)
        session_db.commit()
    return jsonify({"status": "deleted"})


@app.get("/imap/status")
def imap_status():
    err = _check_admin_secret()
    if err:
        return err

    with get_session() as session_db:
        creds = session_db.query(ImapCredential).all()
        if not creds:
            return jsonify({"connected": False})
        return jsonify({"connected": True, "count": len(creds)})


def poll_once():
    with get_session() as session_db:
        imap_creds = session_db.query(ImapCredential).all()
        if not imap_creds:
            logger.info("No IMAP credentials configured; skipping poll.")
            return

        logger.info("Polling IMAP for %s account(s).", len(imap_creds))
        for cred in imap_creds:
            imap_client = None
            try:
                imap_client = connect_imap(cred.imap_host, cred.imap_port, cred.imap_username, cred.imap_password)
                uids = list_unseen_uids(imap_client, cred.imap_folder)
                if not uids:
                    continue

                is_first_run = not session_db.query(ProcessedImapMessage).filter_by(
                    imap_account=cred.imap_username
                ).first()

                if is_first_run:
                    logger.info(
                        "First run for %s: seeding %d existing message(s), replies start from next poll.",
                        cred.imap_username, len(uids),
                    )
                    for uid in uids:
                        uid_str = uid.decode("utf-8", errors="ignore")
                        mark_seen(imap_client, uid)
                        try:
                            session_db.add(ProcessedImapMessage(imap_account=cred.imap_username, imap_uid=uid_str))
                            session_db.commit()
                        except IntegrityError:
                            session_db.rollback()
                    continue

                for uid in uids:
                    uid_str = uid.decode("utf-8", errors="ignore")
                    existing = (
                        session_db.query(ProcessedImapMessage)
                        .filter_by(imap_account=cred.imap_username, imap_uid=uid_str)
                        .one_or_none()
                    )
                    if existing:
                        mark_seen(imap_client, uid)
                        continue

                    message = fetch_message_by_uid(imap_client, uid)
                    if not message:
                        continue

                    parsed = parse_imap_message(message)
                    if not parsed:
                        continue

                    from_email = parsed["from_email"].lower()
                    if from_email == cred.imap_username.lower():
                        mark_seen(imap_client, uid)
                        continue

                    if is_likely_bulk(parsed["headers"], parsed["subject"], parsed["body"], from_email):
                        logger.info("Skipping likely bulk email from %s", from_email)
                        mark_seen(imap_client, uid)
                        continue

                    acct_assistant_id = cred.openai_assistant_id or None
                    cc_addr = None
                    if EMERGENCY_CC_EMAIL:
                        importance = classify_importance(
                            sender_name=parsed["from_name"],
                            sender_email=parsed["from_email"],
                            subject=parsed["subject"],
                            original_body=parsed["body"],
                            assistant_id=acct_assistant_id,
                        )
                        if EMERGENCY_CC_LEVEL == "emergency":
                            if importance == "EMERGENCY":
                                cc_addr = EMERGENCY_CC_EMAIL
                        else:
                            if importance in {"IMPORTANT", "EMERGENCY"}:
                                cc_addr = EMERGENCY_CC_EMAIL

                    reply_text = generate_reply_text(
                        sender_name=parsed["from_name"],
                        sender_email=parsed["from_email"],
                        subject=parsed["subject"],
                        original_body=parsed["body"],
                        assistant_id=acct_assistant_id,
                    )
                    if not reply_text:
                        logger.warning("Assistant returned empty reply for IMAP %s", uid_str)
                        continue

                    send_smtp_reply(
                        to_addr=parsed["reply_to"],
                        subject=parsed["subject"],
                        body=reply_text,
                        in_reply_to=parsed["message_id"],
                        references=parsed["references"],
                        cc_addr=cc_addr,
                        smtp_host=cred.smtp_host,
                        smtp_port=cred.smtp_port,
                        smtp_username=cred.smtp_username,
                        smtp_password=cred.smtp_password,
                        smtp_from=cred.smtp_from,
                    )
                    mark_seen(imap_client, uid)
                    try:
                        session_db.add(
                            ProcessedImapMessage(imap_account=cred.imap_username, imap_uid=uid_str)
                        )
                        session_db.commit()
                    except IntegrityError:
                        session_db.rollback()
                    logger.info("Replied to IMAP message %s for %s", uid_str, cred.imap_username)

            except Exception as exc:  # pylint: disable=broad-except
                logger.exception("IMAP error for %s: %s", cred.imap_username, exc)
            finally:
                if imap_client:
                    try:
                        imap_client.logout()
                    except Exception:  # pylint: disable=broad-except
                        pass


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
