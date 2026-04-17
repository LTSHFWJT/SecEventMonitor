from datetime import UTC, datetime
import unittest
from unittest.mock import patch

import requests

from seceventmonitor.services.collectors.nvd import NvdCollector


class _FakeResponse:
    def __init__(self, payload, *, status_code=200, headers=None):
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error", response=self)

    def json(self):
        return self._payload


class _SequenceSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append({"url": url, "params": params or {}, "timeout": timeout})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class NvdCollectorMetricTest(unittest.TestCase):
    def setUp(self) -> None:
        self.collector = NvdCollector(settings={}, session=object())

    def test_prefers_v40_over_v31(self) -> None:
        item = self.collector._normalize_cve(
            {
                "id": "CVE-2026-0001",
                "published": "2026-04-08T01:02:03.123Z",
                "lastModified": "2026-04-08T05:06:07.456Z",
                "descriptions": [{"lang": "en", "value": "Example vulnerability description"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "attackVector": "NETWORK",
                            },
                        }
                    ],
                    "cvssMetricV40": [
                        {
                            "type": "Primary",
                            "cvssData": {
                                "version": "4.0",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "attackRequirements": "NONE",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "vulnConfidentialityImpact": "HIGH",
                                "vulnIntegrityImpact": "HIGH",
                                "vulnAvailabilityImpact": "HIGH",
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 4.9,
                        }
                    ],
                },
            }
        )

        self.assertEqual(item["cvss_version"], "4.0")
        self.assertEqual(item["base_score"], 8.8)
        self.assertEqual(item["attack_requirements"], "NONE")
        self.assertEqual(item["severity"], "high")
        self.assertEqual(item["title"], "")
        self.assertEqual(item["vuln_status"], None)

    def test_falls_back_to_v31_when_v40_missing(self) -> None:
        item = self.collector._normalize_cve(
            {
                "id": "CVE-2026-0002",
                "published": "2026-04-08T01:02:03Z",
                "lastModified": "2026-04-08T05:06:07Z",
                "descriptions": [{"lang": "en", "value": "Fallback metric description"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 6.5,
                                "baseSeverity": "MEDIUM",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "LOW",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "NONE",
                                "integrityImpact": "NONE",
                                "availabilityImpact": "HIGH",
                            },
                            "exploitabilityScore": 2.8,
                            "impactScore": 3.6,
                        }
                    ]
                },
            }
        )

        self.assertEqual(item["cvss_version"], "3.1")
        self.assertEqual(item["base_severity"], "MEDIUM")
        self.assertEqual(item["attack_vector"], "NETWORK")
        self.assertEqual(item["availability_impact"], "HIGH")
        self.assertEqual(item["severity"], "medium")

    def test_preserves_vuln_status(self) -> None:
        item = self.collector._normalize_cve(
            {
                "id": "CVE-2026-0003",
                "vulnStatus": "Awaiting Analysis",
                "descriptions": [{"lang": "en", "value": "Status mapping example"}],
                "metrics": {},
            }
        )
        self.assertEqual(item["vuln_status"], "Awaiting Analysis")

    def test_extracts_affected_versions_and_remediation(self) -> None:
        item = self.collector._normalize_cve(
            {
                "id": "CVE-2026-0004",
                "descriptions": [{"lang": "en", "value": "Affected version parsing example"}],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "3.0.0",
                                        "versionEndExcluding": "3.0.8",
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                                    },
                                ],
                            }
                        ]
                    }
                ],
                "evaluatorSolution": "Upgrade to version 3.0.8 or later.",
                "vendorComments": [
                    {
                        "organization": "OpenSSL",
                        "comment": "Apply the upstream fix package.",
                    }
                ],
                "cisaRequiredAction": "Follow BOD 22-01 remediation guidance.",
                "metrics": {},
            }
        )

        self.assertIn("[应用] openssl: >= 3.0.0, < 3.0.8", item["affected_versions"])
        self.assertIn("openssl", item["affected_products"])
        self.assertIn("\"product_label\":\"openssl\"", item["affected_version_data"])
        self.assertIn("NVD 解决建议", item["remediation"])
        self.assertIn("Upgrade to version 3.0.8 or later.", item["remediation"])
        self.assertIn("[OpenSSL] Apply the upstream fix package.", item["remediation"])
        self.assertIn("CISA 要求措施", item["remediation"])


class NvdCollectorRetryTest(unittest.TestCase):
    def test_fetch_retries_after_read_timeout(self) -> None:
        session = _SequenceSession(
            [
                requests.ReadTimeout("read timed out"),
                _FakeResponse(
                    {
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": "CVE-2026-0101",
                                    "descriptions": [{"lang": "en", "value": "Retry succeeded"}],
                                    "metrics": {},
                                }
                            }
                        ],
                        "totalResults": 1,
                    }
                ),
            ]
        )
        collector = NvdCollector(settings={}, session=session)
        collector.request_interval_seconds = 0

        with patch("seceventmonitor.services.collectors.nvd.time.sleep") as sleep_mock:
            items = collector.fetch(since=datetime(2026, 4, 8, tzinfo=UTC), limit=1)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["cve_id"], "CVE-2026-0101")
        self.assertEqual(len(session.calls), 2)
        sleep_mock.assert_called_once_with(5.0)

    def test_fetch_retries_after_retry_after_rate_limit(self) -> None:
        session = _SequenceSession(
            [
                _FakeResponse({"message": "rate limited"}, status_code=429, headers={"Retry-After": "1.5"}),
                _FakeResponse({"vulnerabilities": [], "totalResults": 0}),
            ]
        )
        collector = NvdCollector(settings={}, session=session)
        collector.request_interval_seconds = 0

        with patch("seceventmonitor.services.collectors.nvd.time.sleep") as sleep_mock:
            items = collector.fetch(since=datetime(2026, 4, 8, tzinfo=UTC))

        self.assertEqual(items, [])
        self.assertEqual(len(session.calls), 2)
        sleep_mock.assert_called_once_with(1.5)


if __name__ == "__main__":
    unittest.main()
