from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin
from seceventmonitor.utils.timezone import format_datetime


class SyncJobLog(db.Model, TimestampMixin):
    __tablename__ = "sync_job_logs"

    id = db.Column(db.Integer, primary_key=True)
    job_name = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(32), nullable=False, default="idle", index=True)
    message = db.Column(db.Text, nullable=False, default="")
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self, timezone_name: str | None = None):
        return {
            "id": self.id,
            "job_name": self.job_name,
            "status": self.status,
            "message": self.message,
            "started_at": format_datetime(self.started_at, timezone_name),
            "finished_at": format_datetime(self.finished_at, timezone_name),
            "created_at": format_datetime(self.created_at, timezone_name),
            "updated_at": format_datetime(self.updated_at, timezone_name),
        }
