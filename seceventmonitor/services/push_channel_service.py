from seceventmonitor.extensions import db
from seceventmonitor.models import PushChannel
from seceventmonitor.services import settings as settings_service


def list_channels():
    timezone_name = settings_service.get_timezone_name()
    return [item.to_dict(timezone_name=timezone_name) for item in PushChannel.query.order_by(PushChannel.id.asc()).all()]


def update_channel(channel_type: str, **payload):
    channel = PushChannel.query.filter_by(channel_type=channel_type).first()
    if channel is None:
        raise ValueError("推送通道不存在")

    if "name" in payload:
        channel.name = (payload.get("name") or "").strip() or channel.name
    if "enabled" in payload:
        channel.enabled = bool(payload["enabled"])
    if "webhook_url" in payload:
        channel.webhook_url = (payload.get("webhook_url") or "").strip()
    if "secret" in payload:
        channel.secret = (payload.get("secret") or "").strip()
    if "extra_config" in payload and isinstance(payload["extra_config"], dict):
        channel.extra_config = payload["extra_config"]

    db.session.commit()
    return channel.to_dict(timezone_name=settings_service.get_timezone_name())
