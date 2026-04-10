from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin
from seceventmonitor.utils.timezone import format_datetime


class GithubMonitoredTool(db.Model, TimestampMixin):
    __tablename__ = "github_monitored_tools"

    id = db.Column(db.Integer, primary_key=True)
    repo_full_name = db.Column(db.String(255), nullable=False, unique=True, index=True)
    repo_url = db.Column(db.String(500), nullable=False, default="")
    tool_name = db.Column(db.String(255), nullable=False, default="", index=True)
    version = db.Column(db.String(128), nullable=False, default="")
    repo_updated_at = db.Column(db.DateTime, nullable=True, index=True)
    last_synced_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self, timezone_name: str | None = None):
        return {
            "id": self.id,
            "repo_full_name": self.repo_full_name,
            "repo_url": self.repo_url,
            "tool_name": self.tool_name,
            "version": self.version,
            "repo_updated_at": format_datetime(self.repo_updated_at, timezone_name),
            "last_synced_at": format_datetime(self.last_synced_at, timezone_name),
            "created_at": format_datetime(self.created_at, timezone_name),
            "updated_at": format_datetime(self.updated_at, timezone_name),
        }
