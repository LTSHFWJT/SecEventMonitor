from __future__ import annotations

from seceventmonitor.services.collectors.base import BaseCollector
from seceventmonitor.services.collectors.helpers import (
    BROWSER_HEADERS,
    clean_inline_text,
    clean_text,
    extract_cve_id,
    guess_affected_products,
    normalize_severity,
    parse_datetime_value,
    resolve_since,
)


class QianxinTiCollector(BaseCollector):
    source_name = "奇安信威胁情报中心"
    api_url = "https://ti.qianxin.com/alpha-api/v2/vuln/one-day"

    def default_headers(self):
        return {
            **BROWSER_HEADERS,
            "Referer": "https://ti.qianxin.com/",
            "Origin": "https://ti.qianxin.com",
        }

    def fetch(self, since=None, limit=None, progress_callback=None):
        since = resolve_since(since, fallback_days=2)
        response = self.session.post(self.api_url, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data") or {}

        deduplicated = {}
        for value in data.values():
            if not isinstance(value, list):
                continue
            for item in value:
                if not isinstance(item, dict) or not item.get("qvd_code"):
                    continue
                deduplicated[item["qvd_code"]] = item

        records = []
        for item in deduplicated.values():
            compare_time = parse_datetime_value(item.get("latest_update_time") or item.get("update_time") or item.get("publish_time"))
            if compare_time is not None and compare_time < since:
                continue
            records.append(self._normalize_item(item))
            if limit is not None and len(records) >= limit:
                break

        if progress_callback:
            progress_callback(page_index=1, page_size=len(records) or 1, fetched_count=len(records), total_results=len(deduplicated))
        return records

    def _normalize_item(self, item):
        title = clean_inline_text(item.get("vuln_name"))
        description = clean_text(item.get("description"))
        published_at = parse_datetime_value(item.get("publish_time") or item.get("create_time"))
        last_seen_at = parse_datetime_value(item.get("latest_update_time") or item.get("update_time") or item.get("publish_time"))

        return {
            "vuln_key": f"qianxin-ti:{clean_inline_text(item.get('qvd_code'))}",
            "cve_id": extract_cve_id(item.get("cve_code"), title, description),
            "title": title,
            "description": description,
            "description_lang": "zh",
            "severity": normalize_severity(item.get("rating_level")),
            "affected_versions": None,
            "affected_products": guess_affected_products(title, description),
            "affected_version_data": None,
            "remediation": "",
            "source": self.source_name,
            "reference_url": f"https://ti.qianxin.com/vulnerability/detail/{item.get('id')}",
            "published_at": published_at,
            "last_seen_at": last_seen_at or published_at,
            "payload": {
                "tags": [clean_inline_text(tag.get("name")) for tag in item.get("tag") or [] if isinstance(tag, dict)],
                "raw": item,
            },
        }
