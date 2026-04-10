import unittest

from requests import HTTPError, Response

from seceventmonitor.services.collectors.oscs import OscsCollector


class OscsCollectorNormalizationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.collector = OscsCollector(settings={}, session=object())

    def test_merges_legacy_detail_for_remediation_and_references(self) -> None:
        item = {
            "mps": "MPS-8epm-6xq4",
            "url": "",
            "public_time": "2026-04-09T01:02:03Z",
            "updated_at": "2026-04-09T04:05:06Z",
            "level": "high",
        }
        detail = {
            "title": "mlflow 漏洞",
            "description": "Primary description",
            "cve_id": "CVE-2025-15036",
            "level": "high",
            "published_time": "2026-04-09T01:02:03Z",
            "last_modified_time": "2026-04-09T04:05:06Z",
            "fix_suggestion": "Recommend",
            "reference_url_list": [
                {"url": "https://new.example/detail"},
            ],
            "effects": [
                {
                    "comp_name": "mlflow",
                    "versions": [
                        {
                            "affected_version": "(-∞,3.9.0)",
                            "min_fixed_version": "3.9.0",
                            "solutions": [],
                        }
                    ],
                }
            ],
            "cvss": {},
        }
        legacy_detail = {
            "cve_id": "CVE-2025-15036",
            "soulution_data": ["将组件 mlflow 升级至 3.9.0 及以上版本"],
            "vuln_suggest": "Recommend",
            "patch": "",
            "references": [
                {"url": "https://old.example/detail"},
                {"url": "https://new.example/detail"},
            ],
            "effect": [
                {
                    "name": "mlflow",
                    "affected_version": "(-∞,3.9.0)",
                    "min_fixed_version": "3.9.0",
                    "solutions": [
                        {"description": "将组件 mlflow 升级至 3.9.0 及以上版本"},
                    ],
                }
            ],
        }

        normalized = self.collector._normalize_item(item, detail, legacy_detail)

        self.assertEqual(normalized["cve_id"], "CVE-2025-15036")
        self.assertIn("将组件 mlflow 升级至 3.9.0 及以上版本", normalized["remediation"])
        self.assertNotIn("Recommend", normalized["remediation"])
        self.assertIn("https://new.example/detail", normalized["payload"]["references"])
        self.assertIn("https://old.example/detail", normalized["payload"]["references"])
        self.assertEqual(normalized["source_payload"]["legacy_detail"], legacy_detail)
        self.assertIn("[应用] mlflow: < 3.9.0", normalized["affected_versions"])

    def test_skips_item_when_detail_returns_server_error(self) -> None:
        class SkippingCollector(OscsCollector):
            def __init__(self):
                super().__init__(settings={}, session=object())

            def _fetch_list_payload(self, page: int) -> dict:
                if page > 1:
                    return {"data": {"total": 2, "data": []}}
                return {
                    "data": {
                        "total": 2,
                        "data": [
                            {"mps": "MPS-error", "public_time": "2026-04-09T01:02:03Z"},
                            {"mps": "MPS-ok", "public_time": "2026-04-09T01:02:03Z"},
                        ],
                    }
                }

            def _fetch_detail(self, mps: str | None) -> dict:
                if mps == "MPS-error":
                    response = Response()
                    response.status_code = 500
                    response.url = "https://www.oscs1024.com/oscs/v1/vdb/vuln_info/MPS-error"
                    raise HTTPError("500 Server Error", response=response)
                return {"title": "ok", "description": "ok", "effects": [], "cvss": {}}

            def _fetch_legacy_detail(self, mps: str | None) -> dict:
                return {}

            def _load_existing_vulnerabilities(self, rows):
                return {}

            def _normalize_item(self, item, detail, legacy_detail):
                return {"vuln_key": self._build_vuln_key(item)}

        collector = SkippingCollector()
        records = collector.fetch(full_history=True, stop_on_existing=False)

        self.assertEqual(records, [{"vuln_key": "oscs:MPS-ok"}])


if __name__ == "__main__":
    unittest.main()
