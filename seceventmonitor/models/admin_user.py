from datetime import UTC, datetime

from werkzeug.security import check_password_hash, generate_password_hash

from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin
from seceventmonitor.utils.timezone import format_datetime


class AdminUser(db.Model, TimestampMixin):
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    last_login_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def mark_login(self):
        self.last_login_at = datetime.now(UTC).replace(tzinfo=None)

    def to_dict(self, timezone_name: str | None = None):
        return {
            "id": self.id,
            "username": self.username,
            "is_active": self.is_active,
            "last_login_at": format_datetime(self.last_login_at, timezone_name),
        }
