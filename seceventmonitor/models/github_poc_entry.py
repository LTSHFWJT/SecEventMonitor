from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin
from seceventmonitor.utils.timezone import format_datetime


class GithubPocEntry(db.Model, TimestampMixin):
    __tablename__ = "github_poc_entries"

    id = db.Column(db.Integer, primary_key=True)
    poc_key = db.Column(db.String(128), nullable=False, unique=True, index=True)
    cve_id = db.Column(db.String(64), nullable=False, default="", index=True)
    repo_id = db.Column(db.Integer, nullable=False, unique=True, index=True)
    repo_name = db.Column(db.String(255), nullable=False, default="")
    repo_full_name = db.Column(db.String(255), nullable=False, default="", index=True)
    repo_url = db.Column(db.String(500), nullable=False, default="")
    description = db.Column(db.Text, nullable=True)
    owner_login = db.Column(db.String(128), nullable=True, index=True)
    owner_id = db.Column(db.Integer, nullable=True, index=True)
    owner_url = db.Column(db.String(500), nullable=True)
    repo_created_at = db.Column(db.DateTime, nullable=True)
    repo_updated_at = db.Column(db.DateTime, nullable=True, index=True)
    repo_pushed_at = db.Column(db.DateTime, nullable=True, index=True)
    stargazers_count = db.Column(db.Integer, nullable=False, default=0)
    watchers_count = db.Column(db.Integer, nullable=False, default=0)
    forks_count = db.Column(db.Integer, nullable=False, default=0)
    subscribers_count = db.Column(db.Integer, nullable=False, default=0)
    topics = db.Column(db.JSON, nullable=True)
    source_file_path = db.Column(db.String(255), nullable=False, default="", index=True)
    source_file_sha = db.Column(db.String(128), nullable=False, default="")
    source_payload = db.Column(db.JSON, nullable=True)
    status = db.Column(db.String(32), nullable=False, default="new", index=True)
    last_synced_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self, timezone_name: str | None = None):
        topics = self.topics or []
        return {
            "id": self.id,
            "poc_key": self.poc_key,
            "cve_id": self.cve_id,
            "repo_id": self.repo_id,
            "repo_name": self.repo_name,
            "repo_full_name": self.repo_full_name,
            "repo_url": self.repo_url,
            "description": self.description,
            "owner_login": self.owner_login,
            "owner_id": self.owner_id,
            "owner_url": self.owner_url,
            "repo_created_at": format_datetime(self.repo_created_at, timezone_name),
            "repo_updated_at": format_datetime(self.repo_updated_at, timezone_name),
            "repo_pushed_at": format_datetime(self.repo_pushed_at, timezone_name),
            "stargazers_count": self.stargazers_count,
            "watchers_count": self.watchers_count,
            "forks_count": self.forks_count,
            "subscribers_count": self.subscribers_count,
            "topics": topics,
            "topics_text": "、".join(topics) if topics else "-",
            "source_file_path": self.source_file_path,
            "source_file_sha": self.source_file_sha,
            "status": self.status,
            "last_synced_at": format_datetime(self.last_synced_at, timezone_name),
            "created_at": format_datetime(self.created_at, timezone_name),
            "updated_at": format_datetime(self.updated_at, timezone_name),
        }
