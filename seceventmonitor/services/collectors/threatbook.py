from __future__ import annotations

import time

from seceventmonitor.services.collectors.base import BaseCollector
from seceventmonitor.services.collectors.helpers import (
    BROWSER_HEADERS,
    clean_text,
    clean_inline_text,
    collect_unique_lines,
    extract_cve_id,
    guess_affected_products,
    normalize_severity,
    parse_datetime_value,
    resolve_since,
)
from seceventmonitor.utils.affected_versions import (
    build_affected_products_text,
    build_affected_versions_text,
    serialize_affected_entries,
)


class ThreatBookCollector(BaseCollector):
    source_name = "微步在线研究响应中心"
    api_url = "https://x.threatbook.com/v5/node/vul_module/homePage"
    notice_api_url = "https://x.threatbook.com/v5/node/vul_module/notice/next"
    homepage_url = "https://x.threatbook.com/v5/vulIntelligence"
    page_size = 10
    max_pages = 200
    request_interval_seconds = 0.0

    def __init__(self, settings=None, session=None):
        super().__init__(settings=settings, session=session)
        self._last_request_monotonic = None

    def default_headers(self):
        return {
            **BROWSER_HEADERS,
            "Referer": self.homepage_url,
            "Origin": "https://mp.weixin.qq.com",
        }

    def fetch(self, since=None, limit=None, progress_callback=None):
        since = resolve_since(since, fallback_days=30)
        response = self.session.get(self.api_url, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data") or {}

        merged = {}
        for bucket in ("highrisk", "premium"):
            for item in data.get(bucket) or []:
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                merged[item["id"]] = item

        records = []
        for item in merged.values():
            compare_time = parse_datetime_value(item.get("vuln_update_time") or item.get("vuln_publish_time"))
            if compare_time is not None and compare_time < since:
                continue
            records.append(self._normalize_item(item))
            if limit is not None and len(records) >= limit:
                break

        if progress_callback:
            progress_callback(page_index=1, page_size=len(records) or 1, fetched_count=len(records), total_results=len(merged))
        return records

    def fetch_notice_page(self, page_index: int) -> dict:
        self._sleep_before_request()
        response = self.session.get(
            self.notice_api_url,
            params={"page": page_index, "pageSize": self.page_size},
            timeout=self.timeout,
        )
        self._last_request_monotonic = time.monotonic()
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else {}

    def normalize_notice_item(self, item):
        title = clean_inline_text(item.get("title"))
        published_at, last_seen_at = self._extract_notice_times(item)
        affected_entries = self._build_version_entries(item.get("versions") or [])
        remediation_lines = self._build_solution_lines(item.get("solutionsList") or [], item.get("ptempSolution"))
        identifiers = item.get("id") or []
        if not isinstance(identifiers, list):
            identifiers = [identifiers]
        cve_id = extract_cve_id(*(identifiers + [title]))
        vuln_id = clean_inline_text(item.get("xveId"))
        if not vuln_id:
            fallback_id = cve_id or (identifiers[0] if identifiers else title)
            vuln_id = clean_inline_text(fallback_id)

        return {
            "vuln_key": f"threatbook:{vuln_id}",
            "cve_id": cve_id,
            "title": title,
            "description": title,
            "description_lang": "zh",
            "severity": normalize_severity(item.get("riskLevel") or "high"),
            "vector_string": clean_inline_text(item.get("vectorString")) or None,
            "affected_versions": build_affected_versions_text(affected_entries) or clean_text("\n".join(item.get("versions") or [])) or None,
            "affected_products": build_affected_products_text(affected_entries) or guess_affected_products(title),
            "affected_version_data": serialize_affected_entries(affected_entries) if affected_entries else None,
            "remediation": "\n".join(remediation_lines),
            "source": self.source_name,
            "reference_url": self.homepage_url,
            "published_at": published_at,
            "last_seen_at": last_seen_at,
            "payload": item,
        }

    def _normalize_item(self, item):
        title = clean_inline_text(item.get("vuln_name_zh"))
        affected_entries = self._build_affected_entries(item.get("affects") or [])
        return {
            "vuln_key": f"threatbook:{clean_inline_text(item.get('id'))}",
            "cve_id": extract_cve_id(title),
            "title": title,
            "description": title,
            "description_lang": "zh",
            "severity": normalize_severity(item.get("riskLevel") or "high"),
            "affected_versions": build_affected_versions_text(affected_entries) or None,
            "affected_products": build_affected_products_text(affected_entries) or None,
            "affected_version_data": serialize_affected_entries(affected_entries) if affected_entries else None,
            "remediation": "有修复方案" if item.get("solution") else "",
            "source": self.source_name,
            "reference_url": self.homepage_url,
            "published_at": parse_datetime_value(item.get("vuln_publish_time") or item.get("vuln_update_time")),
            "last_seen_at": parse_datetime_value(item.get("vuln_update_time") or item.get("vuln_publish_time")),
            "payload": item,
        }

    def _build_affected_entries(self, affects):
        entries = []
        for value in affects:
            text = clean_inline_text(value).replace(">", "/")
            if not text:
                continue
            entries.append(
                {
                    "part": "a",
                    "part_label": "应用",
                    "vendor": "",
                    "product": text,
                    "product_label": text,
                    "display_label": f"[应用] {text}",
                    "version_exact": None,
                    "version_start_including": None,
                    "version_start_excluding": None,
                    "version_end_including": None,
                    "version_end_excluding": None,
                    "criteria": "",
                }
            )
        return entries

    def _build_version_entries(self, versions):
        entries = []
        for value in versions:
            block = clean_text(value)
            if not block:
                continue
            lines = [clean_inline_text(item) for item in block.splitlines() if clean_inline_text(item)]
            if not lines:
                continue
            product_text = lines[0].replace(">", "/")
            version_lines = lines[1:] or [product_text]
            for line in version_lines:
                entries.append(
                    {
                        "part": "a",
                        "part_label": "应用",
                        "vendor": "",
                        "product": product_text,
                        "product_label": product_text,
                        "display_label": f"[应用] {product_text}",
                        "version_exact": None,
                        "version_start_including": None,
                        "version_start_excluding": None,
                        "version_end_including": None,
                        "version_end_excluding": None,
                        "criteria": clean_inline_text(line),
                    }
                )
        return entries

    def _build_solution_lines(self, solutions, temp_solution):
        blocks = []
        for solution in solutions:
            if not isinstance(solution, dict):
                continue
            source_name = clean_inline_text(solution.get("source"))
            text = clean_text(solution.get("text"))
            if source_name and text:
                blocks.append(f"{source_name}:\n{text}")
            elif text:
                blocks.append(text)
        temp_text = clean_text(temp_solution)
        if temp_text:
            blocks.append(temp_text)
        return collect_unique_lines(*blocks)

    def _extract_notice_times(self, item):
        published_at = None
        earliest_time = None
        last_seen_at = None

        for entry in item.get("timelines") or []:
            if not isinstance(entry, dict):
                continue
            current_time = parse_datetime_value(entry.get("timeline"))
            if current_time is None:
                continue
            if earliest_time is None or current_time < earliest_time:
                earliest_time = current_time
            if last_seen_at is None or current_time > last_seen_at:
                last_seen_at = current_time

            for detail in entry.get("descriptions") or []:
                if not isinstance(detail, dict):
                    continue
                if clean_inline_text(detail.get("field")) == "VULN_PUBLISH_TIME":
                    published_at = current_time

        published_at = published_at or earliest_time
        last_seen_at = last_seen_at or published_at
        return published_at, last_seen_at

    def _sleep_before_request(self):
        if self._last_request_monotonic is None:
            return
        elapsed = time.monotonic() - self._last_request_monotonic
        remaining = self.request_interval_seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)
