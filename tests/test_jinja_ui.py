import json
import os
import re
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import event

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.models import (
    GithubApiConfig,
    GithubMonitoredTool,
    GithubPocEntry,
    PushConfig,
    PushLog,
    SyncJobLog,
    TranslationApiConfig,
    Vulnerability,
    VulnerabilityEvent,
    WatchRule,
)
from seceventmonitor.utils.affected_versions import (
    build_affected_products_text,
    parse_affected_versions_text,
    serialize_affected_entries,
)


class JinjaUiSmokeTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        db.remove()
        if getattr(db, "_engine", None) is not None:
            db._engine.dispose()
        os.environ["APP_SECRET_KEY"] = "test-secret"
        os.environ["SQLITE_DB_PATH"] = str(Path(self._tmpdir.name) / "test.db")
        self.client = TestClient(create_app())

    def tearDown(self) -> None:
        db.remove()
        if getattr(db, "_engine", None) is not None:
            db._engine.dispose()
        os.environ.pop("APP_SECRET_KEY", None)
        os.environ.pop("SQLITE_DB_PATH", None)
        self._tmpdir.cleanup()

    def _setup_admin(self) -> None:
        response = self.client.post(
            "/setup",
            data={
                "username": "admin",
                "password": "pass123",
                "confirm_password": "pass123",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/overview")

    def test_setup_login_and_admin_pages(self) -> None:
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/setup")

        response = self.client.get("/setup")
        self.assertEqual(response.status_code, 200)
        self.assertIn("初始化管理员账号", response.text)

        self._setup_admin()

        overview_response = self.client.get("/overview")
        self.assertEqual(overview_response.status_code, 200)
        self.assertIn("概览", overview_response.text)

        monitor_response = self.client.get("/monitor")
        self.assertEqual(monitor_response.status_code, 200)
        self.assertIn("漏洞列表", monitor_response.text)
        self.assertIn("漏洞编号", monitor_response.text)

        monitor_config_response = self.client.get("/monitor-config")
        self.assertEqual(monitor_config_response.status_code, 200)
        self.assertIn("监控配置", monitor_config_response.text)

        push_response = self.client.get("/push")
        self.assertEqual(push_response.status_code, 200)
        self.assertIn("推送配置", push_response.text)

        settings_response = self.client.get("/settings")
        self.assertEqual(settings_response.status_code, 200)
        self.assertIn("系统设置", settings_response.text)

        logout_response = self.client.post("/logout", follow_redirects=False)
        self.assertEqual(logout_response.status_code, 303)
        self.assertEqual(logout_response.headers["location"], "/login")

        relogin_response = self.client.post(
            "/login",
            data={"username": "admin", "password": "pass123"},
            follow_redirects=False,
        )
        self.assertEqual(relogin_response.status_code, 303)
        self.assertEqual(relogin_response.headers["location"], "/overview")

    def test_monitor_default_page_size_is_10(self) -> None:
        self._setup_admin()

        for index in range(12):
            db.session.add(
                Vulnerability(
                    vuln_key=f"nvd:CVE-2025-{index:04d}",
                    cve_id=f"CVE-2025-{index:04d}",
                    title=f"test vuln {index}",
                    description="desc",
                    severity="high",
                    source="NVD",
                    status="new",
                    reference_url=f"https://example.com/{index}",
                )
            )
        db.session.commit()

        response = self.client.get("/monitor")
        self.assertEqual(response.status_code, 200)
        self.assertIn('option value="10" selected', response.text)

        tbody_match = re.search(r"<tbody>(.*?)</tbody>", response.text, re.S)
        self.assertIsNotNone(tbody_match)
        self.assertEqual(tbody_match.group(1).count("<tr>"), 10)

    def test_push_config_crud_from_push_page(self) -> None:
        self._setup_admin()

        response = self.client.get("/push")
        self.assertEqual(response.status_code, 200)
        self.assertIn("推送配置", response.text)
        self.assertIn("新增推送配置", response.text)
        self.assertIn("推送规则配置列表", response.text)

        create_response = self.client.post(
            "/push/configs",
            data={
                "name": "NVD 高危钉钉",
                "channel_type": "dingding",
                "webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=test",
                "secret": "abc123",
                "enabled": "on",
                "rule_payload": [
                    json.dumps(
                        {
                            "rule_type": "vulnerability",
                            "source": "NVD",
                            "severity_levels": ["high", "critical"],
                            "status": "updated",
                            "affected_products": "openssl\nnginx",
                        }
                    ),
                    json.dumps(
                        {
                            "rule_type": "vulnerability",
                            "source": "all",
                            "severity_levels": ["critical"],
                            "status": "new",
                            "affected_products": "",
                        }
                    ),
                ],
            },
            follow_redirects=False,
        )
        self.assertEqual(create_response.status_code, 303)
        self.assertEqual(create_response.headers["location"], "/push")

        config = PushConfig.query.filter_by(name="NVD 高危钉钉").first()
        self.assertIsNotNone(config)
        self.assertEqual(config.channel_type, "dingding")
        self.assertTrue(config.enabled)
        self.assertEqual(len(config.rule_items or []), 2)
        self.assertEqual(config.rule_items[0]["severity_levels"], ["high", "critical"])

        response = self.client.get("/push")
        self.assertIn("NVD 高危钉钉", response.text)
        self.assertIn("oapi.dingtalk.com", response.text)
        self.assertIn("openssl", response.text)

        config_id = config.id

        toggle_response = self.client.post(f"/push/configs/{config_id}/toggle", follow_redirects=False)
        self.assertEqual(toggle_response.status_code, 303)
        self.assertEqual(toggle_response.headers["location"], "/push")
        db.session.refresh(config)
        self.assertFalse(config.enabled)

        delete_response = self.client.post(f"/push/configs/{config_id}/delete", follow_redirects=False)
        self.assertEqual(delete_response.status_code, 303)
        self.assertEqual(delete_response.headers["location"], "/push")
        db.remove()
        self.assertIsNone(PushConfig.query.filter_by(id=config_id).first())

    def test_push_config_modal_can_send_test_message(self) -> None:
        self._setup_admin()

        with patch("seceventmonitor.jinja_ui.send_test_message_with_payload") as send_mock:
            response = self.client.post(
                "/push/configs/test",
                data={
                    "channel_type": "dingding",
                    "webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=test",
                    "secret": "sec",
                },
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/push")
        send_mock.assert_called_once_with(
            channel_type="dingding",
            webhook_url="https://oapi.dingtalk.com/robot/send?access_token=test",
            secret="sec",
            push_config_id=None,
        )

    def test_monitor_supports_advanced_affected_filters(self) -> None:
        self._setup_admin()

        openssl_entries = parse_affected_versions_text("[应用] openssl: >= 3.0.0, < 3.0.8")
        nginx_entries = parse_affected_versions_text("[应用] nginx: 1.25.3")

        db.session.add(
            Vulnerability(
                vuln_key="nvd:CVE-2026-0101",
                cve_id="CVE-2026-0101",
                description="openssl vuln",
                severity="high",
                source="NVD",
                status="new",
                affected_versions="[应用] openssl: >= 3.0.0, < 3.0.8",
                affected_products=build_affected_products_text(openssl_entries),
                affected_version_data=serialize_affected_entries(openssl_entries),
            )
        )
        db.session.add(
            Vulnerability(
                vuln_key="nvd:CVE-2026-0102",
                cve_id="CVE-2026-0102",
                description="nginx vuln",
                severity="medium",
                source="NVD",
                status="updated",
                affected_versions="[应用] nginx: 1.25.3",
                affected_products=build_affected_products_text(nginx_entries),
                affected_version_data=serialize_affected_entries(nginx_entries),
            )
        )
        db.session.commit()

        response = self.client.get("/monitor?affected_product=openssl&affected_version=3.0.6")
        self.assertEqual(response.status_code, 200)
        self.assertIn("高级搜索", response.text)
        self.assertIn("CVE-2026-0101", response.text)
        self.assertNotIn("CVE-2026-0102", response.text)
        self.assertIn('name="affected_product" value="openssl"', response.text)
        self.assertIn('name="affected_version" value="3.0.6"', response.text)

    def test_monitor_supports_multi_severity_filters(self) -> None:
        self._setup_admin()

        for cve_id, severity in [
            ("CVE-2026-0201", "high"),
            ("CVE-2026-0202", "medium"),
            ("CVE-2026-0203", "low"),
        ]:
            db.session.add(
                Vulnerability(
                    vuln_key=f"nvd:{cve_id}",
                    cve_id=cve_id,
                    description=f"{severity} vuln",
                    severity=severity,
                    source="NVD",
                    status="new",
                )
            )
        db.session.commit()

        response = self.client.get("/monitor?severity=high&severity=medium")
        self.assertEqual(response.status_code, 200)
        self.assertIn("CVE-2026-0201", response.text)
        self.assertIn("CVE-2026-0202", response.text)
        self.assertNotIn("CVE-2026-0203", response.text)
        self.assertRegex(response.text, r'value="high"[^>]*checked|checked[^>]*value="high"')
        self.assertRegex(response.text, r'value="medium"[^>]*checked|checked[^>]*value="medium"')

    def test_vulnerability_detail_shows_affected_versions_and_remediation(self) -> None:
        self._setup_admin()

        vulnerability = Vulnerability(
            vuln_key="nvd:CVE-2026-9999",
            cve_id="CVE-2026-9999",
            description="detail desc",
            severity="high",
            source="NVD",
            status="new",
            reference_url="https://example.com/detail",
            affected_versions="[应用] openssl: >= 3.0.0, < 3.0.8",
            remediation="NVD 解决建议\nUpgrade to 3.0.8 or later.",
        )
        db.session.add(vulnerability)
        db.session.commit()

        response = self.client.get(f"/monitor/vulnerability/{vulnerability.id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("受影响版本", response.text)
        self.assertIn("openssl: &gt;= 3.0.0, &lt; 3.0.8", response.text)
        self.assertIn("解决建议", response.text)
        self.assertIn("Upgrade to 3.0.8 or later.", response.text)

    def test_overview_shows_operational_and_github_metrics(self) -> None:
        self._setup_admin()
        now = datetime.now(UTC).replace(tzinfo=None)

        vulnerability = Vulnerability(
            vuln_key="nvd:CVE-2026-3001",
            cve_id="CVE-2026-3001",
            title="overview vuln",
            description="overview desc",
            severity="critical",
            source="NVD",
            status="new",
            last_seen_at=now,
        )
        db.session.add(vulnerability)
        db.session.flush()

        db.session.add_all(
            [
                VulnerabilityEvent(vulnerability_id=vulnerability.id, event_type="new", message="created"),
                VulnerabilityEvent(vulnerability_id=vulnerability.id, event_type="updated", message="updated"),
                GithubMonitoredTool(
                    repo_full_name="owner/redtool",
                    repo_url="https://github.com/owner/redtool",
                    tool_name="redtool",
                    version="1.2.3",
                    repo_updated_at=now,
                    last_synced_at=now,
                ),
                GithubPocEntry(
                    poc_key="github-poc:1001",
                    cve_id="CVE-2026-3001",
                    repo_id=1001,
                    repo_name="poc-repo",
                    repo_full_name="owner/poc-repo",
                    repo_url="https://github.com/owner/poc-repo",
                    status="new",
                    repo_updated_at=now,
                    repo_pushed_at=now,
                    source_file_path="2026/CVE-2026-3001.json",
                    source_file_sha="sha-1001",
                    last_synced_at=now,
                ),
                PushConfig(
                    name="overview push",
                    channel_type="dingding",
                    webhook_url="https://example.com/webhook",
                    enabled=True,
                ),
                GithubApiConfig(name="overview gh", api_token="ghp_testtoken", enabled=True),
                TranslationApiConfig(app_id="overview-app", api_key="translate-key", enabled=False),
                WatchRule(name="OpenSSL", rule_type="keyword", target="openssl", enabled=True),
                PushLog(status="success", message="ok"),
                PushLog(status="failed", message="failed"),
                SyncJobLog(
                    job_name="sync:nvd",
                    status="success",
                    message="NVD 同步完成",
                    started_at=now,
                    finished_at=now,
                ),
                SyncJobLog(
                    job_name="sync:github_tools",
                    status="running",
                    message="红队工具刷新中",
                    started_at=now,
                ),
            ]
        )
        db.session.commit()

        response = self.client.get("/overview")
        self.assertEqual(response.status_code, 200)
        self.assertIn("监控覆盖", response.text)
        self.assertIn("GitHub监控概况", response.text)
        self.assertIn("同步状态", response.text)
        self.assertIn("GitHub 红队工具", response.text)
        self.assertIn("GitHub POC", response.text)
        self.assertIn("已同步 1 个仓库", response.text)
        self.assertIn("覆盖 CVE 1 个", response.text)
        self.assertIn("红队工具刷新中", response.text)
        self.assertNotIn("CISA KEV 索引 CVE", response.text)
        self.assertNotIn("最近同步任务", response.text)

    def test_overview_limits_database_round_trips(self) -> None:
        self._setup_admin()
        now = datetime.now(UTC).replace(tzinfo=None)

        vulnerability = Vulnerability(
            vuln_key="nvd:CVE-2026-3999",
            cve_id="CVE-2026-3999",
            title="perf vuln",
            description="perf desc",
            severity="high",
            source="NVD",
            status="new",
            last_seen_at=now,
        )
        db.session.add(vulnerability)
        db.session.flush()
        db.session.add(VulnerabilityEvent(vulnerability_id=vulnerability.id, event_type="new", message="created"))
        db.session.commit()

        statements: list[str] = []

        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith(("SELECT", "WITH")):
                statements.append(statement)

        event.listen(db.engine, "before_cursor_execute", before_cursor_execute)
        try:
            response = self.client.get("/overview")
        finally:
            event.remove(db.engine, "before_cursor_execute", before_cursor_execute)

        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(statements), 15)

    def test_docs_endpoints_are_disabled(self) -> None:
        for path in ("/docs", "/redoc", "/openapi.json"):
            response = self.client.get(path, follow_redirects=False)
            self.assertEqual(response.status_code, 404)

    def test_unauthenticated_protected_post_redirects_before_validation(self) -> None:
        self._setup_admin()
        logout_response = self.client.post("/logout", follow_redirects=False)
        self.assertEqual(logout_response.status_code, 303)
        self.assertEqual(logout_response.headers["location"], "/login")

        response = self.client.post("/push/configs/test", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")

    def test_unauthenticated_ajax_request_returns_json_401(self) -> None:
        self._setup_admin()
        self.client.post("/logout", follow_redirects=False)

        response = self.client.post(
            "/push/configs/test",
            headers={
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["status"], "error")
        self.assertIn("未登录", response.json()["message"])


if __name__ == "__main__":
    unittest.main()
