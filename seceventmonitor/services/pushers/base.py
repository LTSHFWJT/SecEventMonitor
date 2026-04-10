from seceventmonitor.services.http_client import build_session


class BasePusher:
    channel_type = "base"
    timeout = 10

    def __init__(self, webhook_url, secret="", proxy_url="", session=None):
        self.webhook_url = (webhook_url or "").strip()
        self.secret = (secret or "").strip()
        self.session = session or build_session(proxy_url=proxy_url)

    def push_message(self, title, content):
        raise NotImplementedError
