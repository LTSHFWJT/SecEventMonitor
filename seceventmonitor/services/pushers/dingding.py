import base64
import hashlib
import hmac
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from seceventmonitor.services.pushers.base import BasePusher


class DingTalkPusher(BasePusher):
    channel_type = "dingding"

    def push_message(self, title, content):
        message_text = self._build_message_text(title, content)
        response = self.session.post(
            self._build_webhook_url(),
            json={
                "msgtype": "text",
                "text": {
                    "content": message_text,
                },
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("errcode") != 0:
            raise RuntimeError(payload.get("errmsg") or "钉钉推送失败")
        return payload

    def _build_webhook_url(self):
        webhook_url = self.webhook_url
        if not webhook_url.startswith("http"):
            webhook_url = f"https://oapi.dingtalk.com/robot/send?access_token={webhook_url}"

        if not self.secret:
            return webhook_url

        timestamp = str(int(time.time() * 1000))
        string_to_sign = f"{timestamp}\n{self.secret}"
        sign = base64.b64encode(
            hmac.new(
                self.secret.encode("utf-8"),
                string_to_sign.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).digest()
        ).decode("utf-8")

        split_result = urlsplit(webhook_url)
        query = dict(parse_qsl(split_result.query, keep_blank_values=True))
        query.update({"timestamp": timestamp, "sign": sign})
        return urlunsplit(
            (
                split_result.scheme,
                split_result.netloc,
                split_result.path,
                urlencode(query),
                split_result.fragment,
            )
        )

    @staticmethod
    def _build_message_text(title, content):
        title_text = str(title or "").strip()
        content_text = str(content or "").strip().replace("\r\n", "\n").replace("\r", "\n")
        if title_text and content_text:
            return f"{title_text}\n{content_text}"
        return title_text or content_text
