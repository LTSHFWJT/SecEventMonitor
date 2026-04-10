from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin
from seceventmonitor.utils.timezone import format_datetime


class TranslationApiConfig(db.Model, TimestampMixin):
    __tablename__ = "translation_api_configs"

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.String(128), nullable=False, unique=True, index=True)
    api_key = db.Column(db.String(255), nullable=False, default="")
    enabled = db.Column(db.Boolean, nullable=False, default=True, index=True)
    last_used_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self, timezone_name: str | None = None):
        return {
            "id": self.id,
            "app_id": self.app_id,
            "api_key": self.api_key,
            "api_key_masked": _mask_api_key(self.api_key),
            "enabled": self.enabled,
            "last_used_at": format_datetime(self.last_used_at, timezone_name),
            "created_at": format_datetime(self.created_at, timezone_name),
            "updated_at": format_datetime(self.updated_at, timezone_name),
        }


def _mask_api_key(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return "-"
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}{'*' * (len(text) - 8)}{text[-4:]}"
