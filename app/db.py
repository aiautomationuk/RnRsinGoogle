import logging
import os
from contextlib import contextmanager

import pymysql
pymysql.install_as_MySQLdb()

from sqlalchemy import create_engine
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
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Database init failed: %s", exc)


@contextmanager
def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
