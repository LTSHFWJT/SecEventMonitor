from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin
from seceventmonitor.utils.timezone import format_datetime


class GithubApiConfig(db.Model, TimestampMixin):
    __tablename__ = "github_api_configs"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, unique=True, index=True)
    api_token = db.Column(db.String(255), nullable=False, default="")
    enabled = db.Column(db.Boolean, nullable=False, default=True, index=True)
    last_used_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self, timezone_name: str | None = None):
        return {
            "id": self.id,
            "name": self.name,
            "api_token": self.api_token,
            "api_token_masked": _mask_api_token(self.api_token),
            "enabled": self.enabled,
            "last_used_at": format_datetime(self.last_used_at, timezone_name),
            "created_at": format_datetime(self.created_at, timezone_name),
            "updated_at": format_datetime(self.updated_at, timezone_name),
        }


def _mask_api_token(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return "-"
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}{'*' * (len(text) - 8)}{text[-4:]}"
