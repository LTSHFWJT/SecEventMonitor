import os
from pathlib import Path


def _resolve_sqlite_db_path() -> Path:
    configured_path = os.getenv("SQLITE_DB_PATH", "").strip()
    if configured_path:
        db_path = Path(configured_path).expanduser()
        if not db_path.is_absolute():
            db_path = Path.cwd() / db_path
        return db_path
    return Path.cwd() / "data" / "sec_event_monitor.db"


class Config:
    APP_NAME = "SecEventMonitor"
    SESSION_COOKIE_NAME = "sec_event_monitor_session"
    ADMIN_SESSION_KEY = "admin_user_id"
    SECRET_KEY = "dev-secret-key"
    SQLITE_DB_PATH = Path.cwd() / "data" / "sec_event_monitor.db"
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{SQLITE_DB_PATH}"
    TIMEZONE = "Asia/Shanghai"

    @classmethod
    def load(cls) -> None:
        cls.SECRET_KEY = os.getenv("APP_SECRET_KEY", "dev-secret-key")
        cls.SQLITE_DB_PATH = _resolve_sqlite_db_path()
        cls.SQLALCHEMY_DATABASE_URI = f"sqlite:///{cls.SQLITE_DB_PATH}"
        cls.TIMEZONE = os.getenv("TIMEZONE", "Asia/Shanghai")

    @classmethod
    def ensure_runtime_dirs(cls) -> None:
        cls.SQLITE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
