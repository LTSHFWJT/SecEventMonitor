from datetime import UTC, datetime

from seceventmonitor.services.http_client import build_session
from seceventmonitor.services.settings import get_settings_map


class BaseCollector:
    source_name = "base"
    timeout = 20

    def __init__(self, settings=None, session=None):
        self.settings = settings if settings is not None else get_settings_map()
        self.session = session or build_session(
            proxy_url=self.settings.get("http_proxy", ""),
            headers=self.default_headers(),
        )

    def default_headers(self):
        return {}

    def fetch(self, since=None, progress_callback=None):
        raise NotImplementedError

    @staticmethod
    def parse_datetime(value):
        if not value:
            return None
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    @staticmethod
    def to_utc_iso(value):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    @staticmethod
    def shorten_text(value, limit=180):
        value = (value or "").strip()
        if len(value) <= limit:
            return value
        return f"{value[: limit - 3]}..."
