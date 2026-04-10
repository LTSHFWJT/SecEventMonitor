import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.models import PushConfig, Vulnerability
from seceventmonitor.services.pushers.service import notify_vulnerability


class PushConfigNotificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        db.remove()
        if getattr(db, "_engine", None) is not None:
            db._engine.dispose()
        os.environ["APP_SECRET_KEY"] = "test-secret"
        os.environ["SQLITE_DB_PATH"] = str(Path(self._tmpdir.name) / "test.db")
        self.app = create_app()

    def tearDown(self) -> None:
        db.remove()
        if getattr(db, "_engine", None) is not None:
            db._engine.dispose()
        os.environ.pop("APP_SECRET_KEY", None)
        os.environ.pop("SQLITE_DB_PATH", None)
        self._tmpdir.cleanup()

    def test_enabled_push_configs_match_any_rule(self) -> None:
        db.session.add(
            PushConfig(
                name="钉钉高危",
                channel_type="dingding",
                enabled=True,
                webhook_url="https://oapi.dingtalk.com/robot/send?access_token=a",
                rule_items=[
                    {
                        "rule_type": "vulnerability",
                        "source": "NVD",
                        "severity_levels": ["critical"],
                        "status": "updated",
                        "affected_products": ["openssl"],
                    },
                    {
                        "rule_type": "vulnerability",
                        "source": "NVD",
                        "severity_levels": ["medium", "high"],
                        "status": "updated",
                        "affected_products": ["openssl"],
                    },
                ],
            )
        )
        db.session.add(
            PushConfig(
                name="飞书不命中",
                channel_type="lark",
                enabled=True,
                webhook_url="https://open.feishu.cn/open-apis/bot/v2/hook/a",
                rule_items=[
                    {
                        "rule_type": "vulnerability",
                        "source": "NVD",
                        "severity_levels": ["critical"],
                        "status": "new",
                        "affected_products": ["nginx"],
                    }
                ],
            )
        )

        vulnerability = Vulnerability(
            vuln_key="nvd:CVE-2026-0001",
            cve_id="CVE-2026-0001",
            description="OpenSSL parsing issue",
            severity="medium",
            source="NVD",
            status="updated",
            affected_products="openssl",
            affected_versions="[应用] openssl: >= 3.0.0, < 3.0.8",
            reference_url="https://example.com/CVE-2026-0001",
        )
        db.session.add(vulnerability)
        db.session.commit()

        with patch("seceventmonitor.services.pushers.service._push_with_log", return_value=1) as push_mock:
            success_count = notify_vulnerability(vulnerability)

        self.assertEqual(success_count, 1)
        self.assertEqual(push_mock.call_count, 1)
        self.assertEqual(push_mock.call_args.kwargs["config"].name, "钉钉高危")


if __name__ == "__main__":
    unittest.main()
