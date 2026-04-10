from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin


class PushLog(db.Model, TimestampMixin):
    __tablename__ = "push_logs"

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(
        db.Integer,
        db.ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    channel_id = db.Column(
        db.Integer,
        db.ForeignKey("push_channels.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    github_tool_id = db.Column(
        db.Integer,
        db.ForeignKey("github_monitored_tools.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    push_config_id = db.Column(
        db.Integer,
        db.ForeignKey("push_configs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)
    message = db.Column(db.Text, nullable=False, default="")
