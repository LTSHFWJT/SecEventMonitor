from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin
from seceventmonitor.utils.timezone import format_datetime


class PushChannel(db.Model, TimestampMixin):
    __tablename__ = "push_channels"

    id = db.Column(db.Integer, primary_key=True)
    channel_type = db.Column(db.String(32), unique=True, nullable=False, index=True)
    name = db.Column(db.String(64), nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=False)
    webhook_url = db.Column(db.String(500), nullable=False, default="")
    secret = db.Column(db.String(255), nullable=False, default="")
    extra_config = db.Column(db.JSON, nullable=True)

    def to_dict(self, timezone_name: str | None = None):
        return {
            "id": self.id,
            "channel_type": self.channel_type,
            "name": self.name,
            "enabled": self.enabled,
            "webhook_url": self.webhook_url,
            "secret_configured": bool(self.secret),
            "extra_config": self.extra_config or {},
            "created_at": format_datetime(self.created_at, timezone_name),
            "updated_at": format_datetime(self.updated_at, timezone_name),
        }
