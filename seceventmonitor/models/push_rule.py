from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin
from seceventmonitor.utils.timezone import format_datetime


class PushRule(db.Model, TimestampMixin):
    __tablename__ = "push_rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    channel_type = db.Column(db.String(32), nullable=False, index=True)
    severity_threshold = db.Column(db.String(16), nullable=False, default="all")
    source = db.Column(db.String(64), nullable=False, default="all")
    status = db.Column(db.String(32), nullable=False, default="all")
    keyword = db.Column(db.String(255), nullable=False, default="")
    enabled = db.Column(db.Boolean, nullable=False, default=True, index=True)

    def to_dict(self, timezone_name: str | None = None):
        return {
            "id": self.id,
            "name": self.name,
            "channel_type": self.channel_type,
            "severity_threshold": self.severity_threshold,
            "source": self.source,
            "status": self.status,
            "keyword": self.keyword,
            "enabled": self.enabled,
            "created_at": format_datetime(self.created_at, timezone_name),
            "updated_at": format_datetime(self.updated_at, timezone_name),
        }
