from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin


class SystemSetting(db.Model, TimestampMixin):
    __tablename__ = "system_settings"

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(32), nullable=False, default="system", index=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=False, default="")
    description = db.Column(db.String(255), nullable=False, default="")

    def to_dict(self):
        return {
            "category": self.category,
            "key": self.key,
            "value": self.value,
            "description": self.description,
        }
