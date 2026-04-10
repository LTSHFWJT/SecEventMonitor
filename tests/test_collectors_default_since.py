import unittest
from datetime import UTC, datetime

from seceventmonitor.services.collectors import github as github_module
from seceventmonitor.services.collectors.github import GitHubCollector
from seceventmonitor.services.collectors.nvd import NvdCollector


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append({"url": url, "params": params or {}, "timeout": timeout})
        return _FakeResponse({"vulnerabilities": [], "totalResults": 0})


class CollectorDefaultSinceTest(unittest.TestCase):
    def test_nvd_first_sync_defaults_to_last_24_hours(self) -> None:
        session = _FakeSession()
        collector = NvdCollector(settings={}, session=session)
        before = datetime.now(UTC)
        collector.fetch()
        after = datetime.now(UTC)

        params = session.calls[0]["params"]
        start = collector.parse_datetime(params["lastModStartDate"])
        end = collector.parse_datetime(params["lastModEndDate"])

        self.assertGreaterEqual((before - start).total_seconds(), 23 * 3600)
        self.assertLessEqual((after - start).total_seconds(), 25 * 3600)
        self.assertGreater(end, start)

    def test_github_first_sync_defaults_to_last_24_hours(self) -> None:
        collector = GitHubCollector(settings={}, session=object())
        captured = {}
        before = datetime.now(UTC)
        original_watch_rule = github_module.WatchRule

        def fake_global_advisories(since, limit=100):
            captured["since"] = since
            return []

        class _FakeWatchRule:
            class query:
                @staticmethod
                def filter_by(**kwargs):
                    class _Result:
                        @staticmethod
                        def all():
                            return []

                    return _Result()

        collector._fetch_global_advisories = fake_global_advisories
        collector._fetch_repo_matches = lambda since, rules: []
        github_module.WatchRule = _FakeWatchRule
        try:
            collector.fetch()
            after = datetime.now(UTC)
        finally:
            github_module.WatchRule = original_watch_rule

        since = captured["since"]
        self.assertGreaterEqual((before - since).total_seconds(), 23 * 3600)
        self.assertLessEqual((after - since).total_seconds(), 25 * 3600)


if __name__ == "__main__":
    unittest.main()
