import re
from datetime import UTC, datetime, timedelta

from seceventmonitor.models import WatchRule
from seceventmonitor.services.collectors.base import BaseCollector


class GitHubCollector(BaseCollector):
    source_name = "github"
    api_base_url = "https://api.github.com"
    cve_pattern = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)

    def default_headers(self):
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        token = (self.settings.get("github_token") or "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def fetch(self, since=None, limit=150, progress_callback=None):
        since = since or (datetime.now(UTC) - timedelta(hours=24))
        records = {}

        for item in self._fetch_global_advisories(since, limit=min(limit, 100)):
            records[item["vuln_key"]] = item

        enabled_rules = WatchRule.query.filter_by(enabled=True).all()
        for item in self._fetch_repo_matches(since, enabled_rules):
            existing = records.get(item["vuln_key"])
            if existing:
                merged_rules = sorted(
                    set(existing["payload"].get("matched_rules", []))
                    | set(item["payload"].get("matched_rules", []))
                )
                existing["payload"]["matched_rules"] = merged_rules
                continue
            records[item["vuln_key"]] = item

        return list(records.values())[:limit]

    def _fetch_global_advisories(self, since, limit=100):
        now = datetime.now(UTC)
        response = self.session.get(
            f"{self.api_base_url}/advisories",
            params={
                "sort": "updated",
                "direction": "desc",
                "per_page": min(limit, 100),
                "updated": f"{since.date().isoformat()}..{now.date().isoformat()}",
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        advisories = response.json()
        return [self._normalize_advisory(item) for item in advisories]

    def _fetch_repo_matches(self, since, rules):
        records = {}
        rule_sets = {"keyword": [], "repo": [], "user": []}
        for rule in rules:
            if rule.rule_type in rule_sets:
                rule_sets[rule.rule_type].append(rule)

        if not any(rule_sets.values()):
            fallback_query = self._search_repositories(
                f"CVE-{datetime.now(UTC).year} pushed:>={self.to_utc_iso(since)}",
                limit=20,
            )
            for repo in fallback_query:
                record = self._normalize_repo(repo, matched_rules=["fallback:CVE-year"])
                records[record["vuln_key"]] = record
            return list(records.values())

        for rule in rule_sets["keyword"]:
            query = f'{rule.target} pushed:>={self.to_utc_iso(since)}'
            for repo in self._search_repositories(query, limit=20):
                record = self._normalize_repo(repo, matched_rules=[f"keyword:{rule.target}"])
                self._merge_record(records, record)

        for rule in rule_sets["user"]:
            response = self.session.get(
                f"{self.api_base_url}/users/{rule.target}/repos",
                params={
                    "sort": "pushed",
                    "direction": "desc",
                    "per_page": 20,
                },
                timeout=self.timeout,
            )
            if response.status_code == 404:
                continue
            response.raise_for_status()
            for repo in response.json():
                pushed_at = self.parse_datetime(repo.get("pushed_at") or repo.get("updated_at"))
                if pushed_at and pushed_at < since:
                    continue
                record = self._normalize_repo(repo, matched_rules=[f"user:{rule.target}"])
                self._merge_record(records, record)

        for rule in rule_sets["repo"]:
            if "/" not in rule.target:
                continue
            response = self.session.get(
                f"{self.api_base_url}/repos/{rule.target}",
                timeout=self.timeout,
            )
            if response.status_code == 404:
                continue
            response.raise_for_status()
            repo = response.json()
            pushed_at = self.parse_datetime(repo.get("pushed_at") or repo.get("updated_at"))
            if pushed_at and pushed_at < since:
                continue
            record = self._normalize_repo(repo, matched_rules=[f"repo:{rule.target}"])
            self._merge_record(records, record)

        return list(records.values())

    def _search_repositories(self, query, limit=20):
        response = self.session.get(
            f"{self.api_base_url}/search/repositories",
            params={
                "q": query,
                "sort": "updated",
                "order": "desc",
                "per_page": min(limit, 100),
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return (response.json() or {}).get("items", [])

    def _normalize_advisory(self, advisory):
        ghsa_id = advisory.get("ghsa_id") or ""
        cve_id = advisory.get("cve_id") or self._first_cve_identifier(advisory.get("identifiers") or [])
        summary = advisory.get("summary") or ghsa_id
        description = (advisory.get("description") or summary or "").strip()

        return {
            "vuln_key": f"github_advisory:{ghsa_id}",
            "cve_id": cve_id,
            "title": self.shorten_text(summary, limit=160),
            "description": description,
            "severity": (advisory.get("severity") or "unknown").lower(),
            "source": "github_advisory",
            "reference_url": advisory.get("html_url") or advisory.get("url") or "",
            "published_at": self.parse_datetime(advisory.get("published_at")),
            "last_seen_at": self.parse_datetime(advisory.get("updated_at")),
            "payload": {
                "ghsa_id": ghsa_id,
                "summary": summary,
                "cvss": advisory.get("cvss"),
                "references": advisory.get("references") or [],
            },
        }

    def _normalize_repo(self, repo, matched_rules):
        description = (repo.get("description") or "GitHub 仓库规则命中").strip()
        combined_text = " ".join(
            [
                repo.get("name") or "",
                repo.get("full_name") or "",
                description,
                " ".join(repo.get("topics") or []),
            ]
        )
        cve_id = ""
        match = self.cve_pattern.search(combined_text)
        if match:
            cve_id = match.group(1).upper()

        return {
            "vuln_key": f"github_repo:{repo.get('id')}",
            "cve_id": cve_id,
            "title": self.shorten_text(repo.get("full_name") or repo.get("name") or "GitHub Repository", limit=160),
            "description": description,
            "severity": self._infer_repo_severity(combined_text),
            "source": "github_repo",
            "reference_url": repo.get("html_url") or "",
            "published_at": self.parse_datetime(repo.get("created_at")),
            "last_seen_at": self.parse_datetime(repo.get("pushed_at") or repo.get("updated_at")),
            "payload": {
                "full_name": repo.get("full_name"),
                "topics": repo.get("topics") or [],
                "language": repo.get("language"),
                "stargazers_count": repo.get("stargazers_count"),
                "matched_rules": matched_rules,
            },
        }

    def _merge_record(self, records, record):
        existing = records.get(record["vuln_key"])
        if existing is None:
            records[record["vuln_key"]] = record
            return
        merged_rules = sorted(
            set(existing["payload"].get("matched_rules", []))
            | set(record["payload"].get("matched_rules", []))
        )
        existing["payload"]["matched_rules"] = merged_rules

    def _first_cve_identifier(self, identifiers):
        for item in identifiers:
            if (item.get("type") or "").upper() == "CVE":
                return item.get("value") or ""
        return ""

    def _infer_repo_severity(self, value):
        lowered = value.lower()
        for severity in ["critical", "high", "medium", "low"]:
            if severity in lowered:
                return severity
        return "unknown"
