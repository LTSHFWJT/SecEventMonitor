from seceventmonitor.config import Config
from seceventmonitor.extensions import db
from seceventmonitor.models import PushChannel, SystemSetting


DEFAULT_SYSTEM_SETTINGS = [
    {
        "category": "monitor",
        "key": "monitor_interval_minutes",
        "value": "60",
        "description": "漏洞同步周期，单位分钟",
    },
    {
        "category": "monitor",
        "key": "github_monitor_interval_minutes",
        "value": "60",
        "description": "Github 同步周期，单位分钟",
    },
    {
        "category": "monitor",
        "key": "nvd_api_key",
        "value": "",
        "description": "NVD API Key",
    },
    {
        "category": "system",
        "key": "timezone",
        "value": "Asia/Shanghai",
        "description": "系统时区",
    },
    {
        "category": "system",
        "key": "http_proxy",
        "value": "",
        "description": "HTTP/HTTPS 代理地址",
    },
]

LEGACY_SYSTEM_SETTING_KEYS = {"github_token", "severity_threshold"}


DEFAULT_PUSH_CHANNELS = [
    {"channel_type": "dingding", "name": "钉钉机器人"},
    {"channel_type": "lark", "name": "飞书机器人"},
]


def ensure_default_settings():
    existing_items = SystemSetting.query.all()
    for item in existing_items:
        if item.key in LEGACY_SYSTEM_SETTING_KEYS:
            db.session.delete(item)
    for item in DEFAULT_SYSTEM_SETTINGS:
        if SystemSetting.query.filter_by(key=item["key"]).first() is not None:
            continue
        db.session.add(SystemSetting(**item))


def ensure_default_push_channels():
    existing_types = {item.channel_type for item in PushChannel.query.all()}
    for item in DEFAULT_PUSH_CHANNELS:
        if item["channel_type"] in existing_types:
            continue
        db.session.add(PushChannel(**item))


def get_settings_map():
    return {item.key: item.value for item in SystemSetting.query.order_by(SystemSetting.key.asc()).all()}


def get_timezone_name():
    value = (get_settings_map().get("timezone") or Config.TIMEZONE or "Asia/Shanghai").strip()
    return value or "Asia/Shanghai"


def get_monitor_interval_minutes(default: int = 60) -> int:
    raw_value = (get_settings_map().get("monitor_interval_minutes") or "").strip()
    try:
        minutes = int(raw_value)
    except (TypeError, ValueError):
        return default
    return max(minutes, 1)


def get_github_monitor_interval_minutes(default: int = 60) -> int:
    raw_value = (get_settings_map().get("github_monitor_interval_minutes") or "").strip()
    try:
        minutes = int(raw_value)
    except (TypeError, ValueError):
        return default
    return max(minutes, 1)


def list_settings():
    return [item.to_dict() for item in SystemSetting.query.order_by(SystemSetting.category.asc(), SystemSetting.key.asc()).all()]


def update_settings(payload):
    default_items = {item["key"]: item for item in DEFAULT_SYSTEM_SETTINGS}
    allowed_keys = {item["key"] for item in DEFAULT_SYSTEM_SETTINGS}
    for key, value in payload.items():
        if key not in allowed_keys:
            continue
        if key in {"monitor_interval_minutes", "github_monitor_interval_minutes"}:
            value = _normalize_monitor_interval_minutes(value)
        setting = SystemSetting.query.filter_by(key=key).first()
        if setting is None:
            default_item = default_items.get(key) or {}
            setting = SystemSetting(
                category=default_item.get("category", "system"),
                key=key,
                value=str(value),
                description=default_item.get("description", ""),
            )
            db.session.add(setting)
        else:
            setting.value = str(value)


def _normalize_monitor_interval_minutes(value) -> str:
    try:
        minutes = int(str(value or "").strip())
    except (TypeError, ValueError):
        raise ValueError("同步周期必须是整数分钟")
    if minutes < 1:
        raise ValueError("同步周期必须大于等于 1 分钟")
    return str(minutes)
