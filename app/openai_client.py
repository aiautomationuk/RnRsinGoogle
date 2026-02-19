import os
import time

from openai import OpenAI


def _client():
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ValueError("OPENAI_API_KEY is required.")
    return OpenAI(api_key=api_key)


def _assistant_id():
    assistant_id = os.environ.get("OPENAI_ASSISTANT_ID", "").strip()
    if not assistant_id:
        raise ValueError("OPENAI_ASSISTANT_ID is required.")
    return assistant_id


def classify_importance(sender_name: str, sender_email: str, subject: str, original_body: str, assistant_id: str | None = None) -> str:
    prompt = (
        "Classify the email urgency as one of: NORMAL, IMPORTANT, EMERGENCY. "
        "IMPORTANT means time-sensitive or high-stakes and should alert a human. "
        "EMERGENCY means immediate action is required. "
        "Return only one word.\n\n"
        f"From: {sender_name} <{sender_email}>\n"
        f"Subject: {subject}\n\n"
        f"Email:\n{original_body}\n"
    )

    client = _client()
    thread = client.beta.threads.create()
    client.beta.threads.messages.create(thread_id=thread.id, role="user", content=prompt)
    run = client.beta.threads.runs.create(thread_id=thread.id, assistant_id=assistant_id or _assistant_id())

    status = run.status
    while status not in {"completed", "failed", "cancelled", "expired"}:
        time.sleep(1)
        run = client.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)
        status = run.status

    if status != "completed":
        return "NORMAL"

    messages = client.beta.threads.messages.list(thread_id=thread.id, order="desc", limit=1)
    if not messages.data or not messages.data[0].content:
        return "NORMAL"

    content = messages.data[0].content[0]
    if getattr(content, "text", None) and getattr(content.text, "value", None):
        value = content.text.value.strip().upper()
        if value in {"NORMAL", "IMPORTANT", "EMERGENCY"}:
            return value

    return "NORMAL"


def generate_reply_text(sender_name: str, sender_email: str, subject: str, original_body: str, assistant_id: str | None = None):
    assistant_id = assistant_id or _assistant_id()

    prompt = (
        "You are an email assistant. Draft a concise, polite reply. "
        "Do not mention you are an AI. Keep it short and actionable.\n\n"
        f"From: {sender_name} <{sender_email}>\n"
        f"Subject: {subject}\n\n"
        f"Email:\n{original_body}\n"
    )

    client = _client()
    thread = client.beta.threads.create()
    client.beta.threads.messages.create(thread_id=thread.id, role="user", content=prompt)
    run = client.beta.threads.runs.create(thread_id=thread.id, assistant_id=assistant_id)

    status = run.status
    while status not in {"completed", "failed", "cancelled", "expired"}:
        time.sleep(1)
        run = client.beta.threads.runs.retrieve(thread_id=thread.id, run_id=run.id)
        status = run.status

    if status != "completed":
        return ""

    messages = client.beta.threads.messages.list(thread_id=thread.id, order="desc", limit=1)
    if not messages.data:
        return ""

    message = messages.data[0]
    if not message.content:
        return ""

    content = message.content[0]
    if getattr(content, "text", None) and getattr(content.text, "value", None):
        return content.text.value.strip()

    return ""

