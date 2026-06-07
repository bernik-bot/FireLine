"""Database engine + session. SQLite by default; set BLACKBIRCH_DB_URL for Postgres."""
import os
from sqlmodel import SQLModel, Session, create_engine

DB_URL = os.environ.get("BLACKBIRCH_DB_URL", "sqlite:///./blackbirch.db")

# check_same_thread only matters for SQLite under FastAPI's threadpool
_connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
engine = create_engine(DB_URL, echo=False, connect_args=_connect_args)


def init_db() -> None:
    # Importing models registers tables on SQLModel.metadata before create_all.
    from app import models  # noqa: F401
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
