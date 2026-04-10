from __future__ import annotations

from seceventmonitor.services.collectors.base import BaseCollector
from seceventmonitor.services.collectors.helpers import BROWSER_HEADERS, clean_inline_text


class KevCollector(BaseCollector):
    source_name = "CISA KEV"
    api_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def default_headers(self):
        return {
            **BROWSER_HEADERS,
            "Referer": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        }

    def fetch(self, since=None, limit=None, progress_callback=None):
        response = self.session.get(self.api_url, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities") or []
        records = []
        for item in vulnerabilities:
            cve_id = clean_inline_text(item.get("cveID")).upper()
            if not cve_id:
                continue
            records.append({"cve_id": cve_id})
            if limit is not None and len(records) >= limit:
                break
        if progress_callback:
            progress_callback(page_index=1, page_size=len(records) or 1, fetched_count=len(records), total_results=len(vulnerabilities))
        return records
