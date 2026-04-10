from __future__ import annotations

import asyncio
import threading

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    func,
)
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker
from sqlalchemy.pool import NullPool


class SQLAlchemyCompat:
    def __init__(self) -> None:
        self.Model = declarative_base()
        self.Column = Column
        self.Integer = Integer
        self.String = String
        self.Text = Text
        self.Boolean = Boolean
        self.DateTime = DateTime
        self.Float = Float
        self.ForeignKey = ForeignKey
        self.JSON = JSON
        self.func = func
        self._engine = None
        self._session_factory = scoped_session(
            sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False),
            scopefunc=self._scopefunc,
        )
        self.Model.query = self._session_factory.query_property()

    def init(self, database_uri: str) -> None:
        connect_args = {}
        engine_kwargs = {"future": True, "connect_args": connect_args}

        if self._engine is not None:
            self.remove()
            self._engine.dispose()

        if database_uri.startswith("sqlite:///"):
            connect_args["check_same_thread"] = False
            connect_args["timeout"] = 30
            # File-based SQLite is more stable here without QueuePool;
            # each unit of work opens/closes its own connection.
            engine_kwargs["poolclass"] = NullPool
        else:
            engine_kwargs["pool_pre_ping"] = True

        self._engine = create_engine(database_uri, **engine_kwargs)
        self._session_factory.configure(bind=self._engine)
        self.Model.metadata.bind = self._engine

    @property
    def engine(self):
        if self._engine is None:
            raise RuntimeError("database engine is not initialized")
        return self._engine

    @property
    def session(self):
        return self._session_factory

    def create_all(self) -> None:
        self.Model.metadata.create_all(bind=self.engine)

    def remove(self) -> None:
        self._session_factory.remove()

    @staticmethod
    def _scopefunc():
        try:
            task = asyncio.current_task()
        except RuntimeError:
            task = None
        return task or threading.get_ident()


db = SQLAlchemyCompat()
