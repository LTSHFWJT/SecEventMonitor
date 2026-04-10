from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin
from seceventmonitor.utils.timezone import format_datetime


class PushConfig(db.Model, TimestampMixin):
    __tablename__ = "push_configs"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    channel_type = db.Column(db.String(32), nullable=False, index=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True, index=True)
    webhook_url = db.Column(db.String(500), nullable=False, default="")
    secret = db.Column(db.String(255), nullable=False, default="")
    rule_items = db.Column(db.JSON, nullable=True)

    def to_dict(self, timezone_name: str | None = None):
        return {
            "id": self.id,
            "name": self.name,
            "channel_type": self.channel_type,
            "enabled": self.enabled,
            "webhook_url": self.webhook_url,
            "secret_configured": bool(self.secret),
            "rule_items": self.rule_items or [],
            "created_at": format_datetime(self.created_at, timezone_name),
            "updated_at": format_datetime(self.updated_at, timezone_name),
        }
