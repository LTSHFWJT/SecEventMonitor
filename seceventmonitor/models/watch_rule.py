from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin
from seceventmonitor.utils.timezone import format_datetime


class WatchRule(db.Model, TimestampMixin):
    __tablename__ = "watch_rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    rule_type = db.Column(db.String(32), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    description = db.Column(db.String(255), nullable=False, default="")

    def to_dict(self, timezone_name: str | None = None):
        return {
            "id": self.id,
            "name": self.name,
            "rule_type": self.rule_type,
            "target": self.target,
            "enabled": self.enabled,
            "description": self.description,
            "created_at": format_datetime(self.created_at, timezone_name),
            "updated_at": format_datetime(self.updated_at, timezone_name),
        }
