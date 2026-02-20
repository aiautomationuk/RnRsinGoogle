import logging
import os
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from .models import Base


logger = logging.getLogger("email-responder")


def _database_url():
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url:
        raise ValueError("DATABASE_URL is required.")
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql://", 1)
    return database_url


_connect_timeout = int(os.environ.get("DB_CONNECT_TIMEOUT", "5"))
_db_url = _database_url()
_connect_args = {}
if "mysql" not in _db_url:
    _connect_args = {"connect_timeout": _connect_timeout}
engine = create_engine(
    _db_url,
    pool_pre_ping=True,
    connect_args=_connect_args,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        db_url = str(engine.url)
        with engine.connect() as conn:
            if "postgresql" in db_url:
                conn.execute(text(
                    "ALTER TABLE imap_credentials ADD COLUMN IF NOT EXISTS openai_assistant_id VARCHAR(128)"
                ))
                conn.execute(text(
                    "ALTER TABLE imap_credentials DROP CONSTRAINT IF EXISTS imap_credentials_user_id_key"
                ))
            else:
                # MySQL/MariaDB: IF NOT EXISTS not supported in ALTER TABLE ADD COLUMN
                r = conn.execute(text(
                    "SELECT COUNT(*) FROM information_schema.columns "
                    "WHERE table_schema=DATABASE() AND table_name='imap_credentials' "
                    "AND column_name='openai_assistant_id'"
                ))
                if r.scalar() == 0:
                    conn.execute(text(
                        "ALTER TABLE imap_credentials ADD COLUMN openai_assistant_id VARCHAR(128)"
                    ))
                r2 = conn.execute(text(
                    "SELECT COUNT(*) FROM information_schema.table_constraints "
                    "WHERE table_schema=DATABASE() AND table_name='imap_credentials' "
                    "AND constraint_name='imap_credentials_user_id_key'"
                ))
                if r2.scalar() > 0:
                    conn.execute(text(
                        "ALTER TABLE imap_credentials DROP INDEX imap_credentials_user_id_key"
                    ))
            conn.commit()
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Database init failed: %s", exc)


@contextmanager
def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
