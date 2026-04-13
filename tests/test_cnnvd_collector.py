from __future__ import annotations

import unittest
from datetime import UTC, datetime

from seceventmonitor.services.collectors.cnnvd import CnnvdCollector


class CnnvdCollectorNormalizationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.collector = CnnvdCollector(settings={}, session=object())

    def test_normalizes_detail_payload(self) -> None:
        row = {
            "id": "4ec7df68cbe7460db5bcd2b102dd8176",
            "vulName": "itsourcecode Construction Management System SQL注入漏洞",
            "cnnvdCode": "CNNVD-202604-2173",
            "cveCode": "CVE-2026-5823",
            "hazardLevel": 3,
            "publishTime": "2026-04-09",
            "updateTime": "2026-04-12",
            "vulType": "0",
        }
        detail = {
            "cnnvdCode": "CNNVD-202604-2173",
            "cveCode": "CVE-2026-5823",
            "publishTime": "2026-04-09 00:00:00",
            "updateTime": "2026-04-10 00:00:00",
            "hazardLevel": 3,
            "vulDesc": (
                "itsourcecode Construction Management System是itsourcecode开源的一个施工管理系统。\n"
                "itsourcecode Construction Management System 1.0版本存在SQL注入漏洞。"
            ),
            "affectedVendor": "itsourcecode",
            "patch": "https://example.com/patch",
            "referUrl": "来源:github.com\n链接:https://example.com/advisory",
        }

        normalized = self.collector._normalize_item(
            row,
            detail,
            published_at=datetime(2026, 4, 9, tzinfo=UTC),
            last_seen_at=datetime(2026, 4, 12, tzinfo=UTC),
        )

        self.assertEqual(normalized["vuln_key"], "cnnvd:CNNVD-202604-2173")
        self.assertEqual(normalized["cve_id"], "CVE-2026-5823")
        self.assertEqual(normalized["severity"], "medium")
        self.assertEqual(normalized["base_severity"], "MEDIUM")
        self.assertEqual(normalized["source"], "CNNVD")
        self.assertEqual(normalized["description_lang"], "zh")
        self.assertEqual(normalized["patch_status"], "AVAILABLE")
        self.assertEqual(normalized["remediation"], "补丁链接: https://example.com/patch")
        self.assertTrue(normalized["affected_products"])
        self.assertIn("itsourcecode", normalized["affected_products"].lower())
        self.assertTrue(normalized["reference_url"].startswith("https://www.cnnvd.org.cn/home/loophole"))
        self.assertEqual(normalized["payload"]["references"], ["https://example.com/advisory"])
        self.assertEqual(normalized["source_payload"]["detail"], detail)

    def test_fetch_stops_when_first_page_hits_existing_record(self) -> None:
        class ExistingCnnvdCollector(CnnvdCollector):
            def __init__(self):
                super().__init__(settings={}, session=object())

            def _fetch_list_payload(self, page_index: int) -> dict:
                if page_index > 1:
                    return {"data": {"total": 1, "records": []}}
                return {
                    "data": {
                        "total": 1,
                        "records": [
                            {
                                "id": "item-1",
                                "cnnvdCode": "CNNVD-202604-2173",
                                "publishTime": "2026-04-09",
                                "updateTime": "2026-04-12",
                                "vulType": "0",
                            }
                        ],
                    }
                }

            def _fetch_detail(self, row: dict) -> dict:
                raise AssertionError("detail fetch should not happen once an up-to-date record is detected")

            def _load_existing_vulnerabilities(self, rows: list[dict]):
                return {
                    "cnnvd:CNNVD-202604-2173": type(
                        "_Existing",
                        (),
                        {
                            "last_seen_at": datetime(2026, 4, 12, tzinfo=UTC),
                            "published_at": datetime(2026, 4, 9, tzinfo=UTC),
                        },
                    )()
                }

        collector = ExistingCnnvdCollector()
        records = collector.fetch(full_history=True, stop_on_existing=True)

        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
