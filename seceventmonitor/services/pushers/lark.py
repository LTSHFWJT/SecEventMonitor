import base64
import hashlib
import hmac
import time

from seceventmonitor.services.pushers.base import BasePusher


class LarkPusher(BasePusher):
    channel_type = "lark"

    def push_message(self, title, content):
        body = {
            "msg_type": "text",
            "content": {
                "text": f"{title}\n{content}",
            },
        }
        if self.secret:
            timestamp = str(int(time.time()))
            string_to_sign = f"{timestamp}\n{self.secret}"
            body["timestamp"] = timestamp
            body["sign"] = base64.b64encode(
                hmac.new(
                    string_to_sign.encode("utf-8"),
                    digestmod=hashlib.sha256,
                ).digest()
            ).decode("utf-8")

        response = self.session.post(
            self._build_webhook_url(),
            json=body,
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        status_code = payload.get("code", payload.get("StatusCode", 0))
        if status_code != 0:
            raise RuntimeError(payload.get("msg") or payload.get("StatusMessage") or "飞书推送失败")
        return payload

    def _build_webhook_url(self):
        if self.webhook_url.startswith("http"):
            return self.webhook_url
        return f"https://open.feishu.cn/open-apis/bot/v2/hook/{self.webhook_url}"
