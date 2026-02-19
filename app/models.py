from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    google_sub = Column(String(128), unique=True, nullable=False)
    email = Column(String(320), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    gmail_token = relationship("GmailToken", back_populates="user", uselist=False)
    imap_credentials = relationship("ImapCredential", back_populates="user")


class GmailToken(Base):
    __tablename__ = "gmail_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    token_json = Column(JSON, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="gmail_token")


class ProcessedMessage(Base):
    __tablename__ = "processed_messages"
    __table_args__ = (UniqueConstraint("user_id", "message_id", name="uq_user_message"),)

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message_id = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ImapCredential(Base):
    __tablename__ = "imap_credentials"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    imap_host = Column(String(255), nullable=False)
    imap_port = Column(Integer, default=993, nullable=False)
    imap_username = Column(String(320), nullable=False)
    imap_password = Column(String(512), nullable=False)
    imap_folder = Column(String(128), default="INBOX", nullable=False)
    smtp_host = Column(String(255), nullable=False)
    smtp_port = Column(Integer, default=2525, nullable=False)
    smtp_username = Column(String(320), nullable=False)
    smtp_password = Column(String(512), nullable=False)
    smtp_from = Column(String(320), nullable=False)
    openai_assistant_id = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="imap_credentials")


class ProcessedImapMessage(Base):
    __tablename__ = "processed_imap_messages"
    __table_args__ = (UniqueConstraint("imap_account", "imap_uid", name="uq_imap_uid"),)

    id = Column(Integer, primary_key=True)
    imap_account = Column(String(320), nullable=False)
    imap_uid = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
