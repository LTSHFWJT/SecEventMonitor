from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from seceventmonitor.config import Config

DEFAULT_TIMEZONE = "Asia/Shanghai"
DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_DATE_FORMAT = "%Y-%m-%d"


def normalize_timezone_name(timezone_name: str | None = None) -> str:
    value = (timezone_name or Config.TIMEZONE or DEFAULT_TIMEZONE).strip()
    return value or DEFAULT_TIMEZONE


@lru_cache(maxsize=32)
def _load_zoneinfo(timezone_name: str) -> ZoneInfo:
    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        return ZoneInfo(DEFAULT_TIMEZONE)


def resolve_timezone(timezone_name: str | None = None) -> ZoneInfo:
    return _load_zoneinfo(normalize_timezone_name(timezone_name))


def parse_datetime_value(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value

    text = str(value).strip()
    if not text:
        return None

    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass

    for fmt in [DEFAULT_DATETIME_FORMAT, "%Y-%m-%d %H:%M:%S.%f", DEFAULT_DATE_FORMAT]:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def to_timezone_datetime(value: datetime | str | None, timezone_name: str | None = None) -> datetime | None:
    parsed = parse_datetime_value(value)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    else:
        parsed = parsed.astimezone(UTC)
    return parsed.astimezone(resolve_timezone(timezone_name))


def format_datetime(value: datetime | str | None, timezone_name: str | None = None, fmt: str = DEFAULT_DATETIME_FORMAT) -> str | None:
    localized = to_timezone_datetime(value, timezone_name)
    if localized is None:
        return None
    return localized.strftime(fmt)


def format_date(value: datetime | str | None, timezone_name: str | None = None) -> str | None:
    return format_datetime(value, timezone_name, fmt=DEFAULT_DATE_FORMAT)
