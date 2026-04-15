from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from seceventmonitor.config import Config
from seceventmonitor.extensions import db
from seceventmonitor.jinja_ui import AdminSessionGuardMiddleware, register_jinja_ui
from seceventmonitor.services.bootstrap import initialize_database, seed_default_records
from seceventmonitor.services.scheduler_service import start_scheduler, stop_scheduler

# Ensure SQLAlchemy models are imported before metadata creation.
from seceventmonitor import models  # noqa: F401


def create_app() -> FastAPI:
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")

    Config.load()
    Config.ensure_runtime_dirs()
    db.init(Config.SQLALCHEMY_DATABASE_URI)
    initialize_database()
    seed_default_records()
    db.remove()

    app = FastAPI(
        title=Config.APP_NAME,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(AdminSessionGuardMiddleware)
    app.add_middleware(
        SessionMiddleware,
        secret_key=Config.SECRET_KEY,
        session_cookie=Config.SESSION_COOKIE_NAME,
        same_site="lax",
    )

    @app.middleware("http")
    async def db_session_cleanup(request, call_next):
        try:
            response = await call_next(request)
            return response
        finally:
            db.remove()

    @app.on_event("startup")
    async def startup_scheduler() -> None:
        start_scheduler()

    @app.on_event("shutdown")
    async def shutdown_scheduler() -> None:
        stop_scheduler()

    @app.get("/api/health")
    async def health():
        return {"status": "success", "message": "ok", "data": {"service": "seceventmonitor", "ready": True}}

    register_jinja_ui(app)
    return app
