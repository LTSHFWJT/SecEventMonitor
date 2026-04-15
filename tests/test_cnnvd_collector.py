from __future__ import annotations

import unittest
from datetime import UTC, datetime

from requests import HTTPError, Response

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

    def test_iter_batches_yields_smaller_chunks_for_incremental_commits(self) -> None:
        class ChunkingCollector(CnnvdCollector):
            def __init__(self):
                super().__init__(settings={}, session=object())
                self.page_size = 25
                self.yield_batch_size = 10
                self.max_pages = 1

            def _fetch_list_payload(self, page_index: int) -> dict:
                return {
                    "data": {
                        "total": 25,
                        "records": [
                            {
                                "id": f"item-{index}",
                                "cnnvdCode": f"CNNVD-202604-{index:04d}",
                                "publishTime": "2026-04-09",
                                "updateTime": "2026-04-10",
                                "vulType": "0",
                            }
                            for index in range(1, 26)
                        ],
                    }
                }

            def _fetch_detail(self, row: dict) -> dict:
                return {"vulName": row["cnnvdCode"]}

            def _load_existing_vulnerabilities(self, rows: list[dict]):
                return {}

            def _normalize_item(self, row: dict, detail: dict, *, published_at=None, last_seen_at=None) -> dict:
                return {"vuln_key": self._build_vuln_key(row)}

        collector = ChunkingCollector()

        batch_sizes = [len(batch) for batch in collector.iter_batches(full_history=True, stop_on_existing=False)]

        self.assertEqual(batch_sizes, [10, 10, 5])

    def test_falls_back_to_list_item_when_detail_request_is_rate_limited(self) -> None:
        class RateLimitedCollector(CnnvdCollector):
            def __init__(self):
                super().__init__(settings={}, session=object())
                self.max_pages = 1

            def _fetch_list_payload(self, page_index: int) -> dict:
                return {
                    "data": {
                        "total": 1,
                        "records": [
                            {
                                "id": "item-1",
                                "vulName": "Example from list",
                                "cnnvdCode": "CNNVD-202604-9999",
                                "cveCode": "CVE-2026-9999",
                                "hazardLevel": 2,
                                "publishTime": "2026-04-09",
                                "updateTime": "2026-04-10",
                                "vulType": "0",
                            }
                        ],
                    }
                }

            def _fetch_detail(self, row: dict) -> dict:
                response = Response()
                response.status_code = 429
                response.url = "https://www.cnnvd.org.cn/web/cnnvdVul/getCnnnvdDetailOnDatasource"
                raise HTTPError("429 Too Many Requests", response=response)

            def _load_existing_vulnerabilities(self, rows: list[dict]):
                return {}

        collector = RateLimitedCollector()
        records = collector.fetch(full_history=True, stop_on_existing=False)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["vuln_key"], "cnnvd:CNNVD-202604-9999")
        self.assertEqual(records[0]["title"], "Example from list")
        self.assertEqual(records[0]["description"], "Example from list")
        self.assertEqual(records[0]["source_payload"]["detail"], {})


if __name__ == "__main__":
    unittest.main()
