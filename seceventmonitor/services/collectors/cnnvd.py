from __future__ import annotations

import logging
import re
import time
from datetime import UTC

from requests import RequestException

from seceventmonitor.models import Vulnerability
from seceventmonitor.services.collectors.base import BaseCollector
from seceventmonitor.services.collectors.helpers import (
    BROWSER_HEADERS,
    build_entry_from_simple_range,
    build_product_only_entry,
    clean_inline_text,
    clean_text,
    collect_unique_lines,
    extract_cve_id,
    guess_affected_products,
    parse_datetime_value,
    resolve_since,
)
from seceventmonitor.utils.affected_versions import (
    build_affected_products_text,
    build_affected_versions_text,
    serialize_affected_entries,
)


_URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)
logger = logging.getLogger(__name__)


class CnnvdCollector(BaseCollector):
    source_name = "CNNVD"
    base_url = "https://www.cnnvd.org.cn"
    list_url = "https://www.cnnvd.org.cn/web/homePage/cnnvdVulList"
    detail_url = "https://www.cnnvd.org.cn/web/cnnvdVul/getCnnnvdDetailOnDatasource"
    page_size = 50
    yield_batch_size = 10
    max_pages = 500
    request_interval_seconds = 2.0

    def __init__(self, settings=None, session=None):
        super().__init__(settings=settings, session=session)
        self._last_request_monotonic = None

    def default_headers(self):
        return {
            **BROWSER_HEADERS,
            "Content-Type": "application/json;charset=UTF-8",
            "Referer": f"{self.base_url}/",
            "Origin": self.base_url,
        }

    def fetch(
        self,
        since=None,
        limit=None,
        progress_callback=None,
        *,
        full_history: bool = False,
        stop_on_existing: bool = True,
    ):
        records = []
        for batch in self.iter_batches(
            since=since,
            limit=limit,
            progress_callback=progress_callback,
            full_history=full_history,
            stop_on_existing=stop_on_existing,
        ):
            records.extend(batch)
            if limit is not None and len(records) >= limit:
                return records[:limit]

        return records

    def iter_batches(
        self,
        since=None,
        limit=None,
        progress_callback=None,
        *,
        full_history: bool = False,
        stop_on_existing: bool = True,
    ):
        threshold = None if full_history else resolve_since(since, fallback_days=30)
        page_index = 1
        fetched_count = 0
        batch_size = max(int(self.yield_batch_size or self.page_size or 1), 1)

        while self.max_pages <= 0 or page_index <= self.max_pages:
            payload = self._fetch_list_payload(page_index)
            data = payload.get("data") or {}
            rows = data.get("records") or []
            total_results = data.get("total")
            if not rows:
                break

            all_before_since = threshold is not None
            should_stop = False
            existing_map = self._load_existing_vulnerabilities(rows) if stop_on_existing else {}
            batch_records = []

            for row in rows:
                published_at = parse_datetime_value(row.get("publishTime") or row.get("createTime"))
                last_seen_at = parse_datetime_value(
                    row.get("updateTime") or row.get("createTime") or row.get("publishTime")
                )
                compare_time = last_seen_at or published_at

                if threshold is not None:
                    if compare_time is None or compare_time >= threshold:
                        all_before_since = False
                    if compare_time is not None and compare_time < threshold:
                        continue

                vuln_key = self._build_vuln_key(row)
                existing = existing_map.get(vuln_key)
                if stop_on_existing and self._is_existing_up_to_date(existing, compare_time):
                    should_stop = True
                    break

                try:
                    detail = self._fetch_detail(row)
                except RequestException as exc:
                    if not self._should_skip_detail_error(exc):
                        raise
                    logger.warning(
                        "Use list-only CNNVD item due to detail fetch error: cnnvd_code=%s error=%s",
                        clean_inline_text(row.get("cnnvdCode")),
                        exc,
                    )
                    detail = {}
                except ValueError as exc:
                    logger.warning(
                        "Use list-only CNNVD item due to detail payload parse error: cnnvd_code=%s error=%s",
                        clean_inline_text(row.get("cnnvdCode")),
                        exc,
                    )
                    detail = {}
                batch_records.append(
                    self._normalize_item(
                        row,
                        detail,
                        published_at=published_at,
                        last_seen_at=last_seen_at,
                    )
                )
                fetched_count += 1

                if len(batch_records) >= batch_size:
                    yield batch_records
                    batch_records = []

                if limit is not None and fetched_count >= limit:
                    if batch_records:
                        yield batch_records
                    if progress_callback:
                        progress_callback(
                            page_index=page_index,
                            page_size=self.page_size,
                            fetched_count=fetched_count,
                            total_results=total_results,
                        )
                    return

            if batch_records:
                yield batch_records

            if progress_callback:
                progress_callback(
                    page_index=page_index,
                    page_size=self.page_size,
                    fetched_count=fetched_count,
                    total_results=total_results,
                )

            if should_stop or (threshold is not None and all_before_since) or len(rows) < self.page_size:
                break

            page_index += 1

    def _fetch_list_payload(self, page_index: int) -> dict:
        self._sleep_before_request()
        response = self.session.post(
            self.list_url,
            json={
                "pageIndex": page_index,
                "pageSize": min(max(int(self.page_size or 50), 1), 50),
                "keyword": "",
                "hazardLevel": "",
                "vulType": "",
                "vendor": "",
                "product": "",
                "dateType": "",
            },
            timeout=self.timeout,
        )
        self._last_request_monotonic = time.monotonic()
        response.raise_for_status()
        return response.json()

    def _fetch_detail(self, row: dict) -> dict:
        self._sleep_before_request()
        response = self.session.post(
            self.detail_url,
            json={
                "id": clean_inline_text(row.get("id")),
                "vulType": clean_inline_text(row.get("vulType")) or "0",
                "cnnvdCode": clean_inline_text(row.get("cnnvdCode")),
            },
            timeout=self.timeout,
        )
        self._last_request_monotonic = time.monotonic()
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return {}
        data = payload.get("data") or {}
        detail = data.get("cnnvdDetail")
        return detail if isinstance(detail, dict) else {}

    def _sleep_before_request(self):
        if self._last_request_monotonic is None:
            return
        elapsed = time.monotonic() - self._last_request_monotonic
        remaining = self.request_interval_seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)

    @staticmethod
    def _should_skip_detail_error(exc: RequestException) -> bool:
        response = getattr(exc, "response", None)
        status_code = getattr(response, "status_code", None)
        return bool(status_code in {403, 429} or (status_code and int(status_code) >= 500))

    def _load_existing_vulnerabilities(self, rows: list[dict]) -> dict[str, Vulnerability]:
        vuln_keys = [self._build_vuln_key(item) for item in rows if self._build_vuln_key(item)]
        if not vuln_keys:
            return {}
        items = Vulnerability.query.filter(Vulnerability.vuln_key.in_(vuln_keys)).all()
        return {item.vuln_key: item for item in items}

    def _is_existing_up_to_date(self, vulnerability: Vulnerability | None, compare_time) -> bool:
        if vulnerability is None:
            return False
        if compare_time is None:
            return True

        existing_compare = vulnerability.last_seen_at or vulnerability.published_at
        if existing_compare is None:
            return True
        if existing_compare.tzinfo is None:
            existing_compare = existing_compare.replace(tzinfo=UTC)
        else:
            existing_compare = existing_compare.astimezone(UTC)
        return existing_compare >= compare_time

    @staticmethod
    def _build_vuln_key(item: dict) -> str:
        cnnvd_code = clean_inline_text(item.get("cnnvdCode")).upper()
        return f"cnnvd:{cnnvd_code}" if cnnvd_code else ""

    def _normalize_item(self, row: dict, detail: dict, *, published_at=None, last_seen_at=None) -> dict:
        title = clean_inline_text(detail.get("vulName") or row.get("vulName"))
        description = clean_text(detail.get("vulDesc")) or title
        cve_id = extract_cve_id(detail.get("cveCode"), row.get("cveCode"), title, description)
        references = self._build_references(detail)
        affected_entries = self._build_affected_entries(detail, title, description)

        detail_published_at = parse_datetime_value(detail.get("publishTime"))
        detail_last_seen_at = parse_datetime_value(detail.get("updateTime"))
        published_at = detail_published_at or published_at
        last_seen_at = last_seen_at or detail_last_seen_at or published_at

        return {
            "vuln_key": self._build_vuln_key(row),
            "cve_id": cve_id,
            "title": title,
            "description": description,
            "description_lang": "zh",
            "severity": self._normalize_hazard_level(detail.get("hazardLevel"), row.get("hazardLevel")),
            "base_severity": self._normalize_base_severity(detail.get("hazardLevel"), row.get("hazardLevel")),
            "affected_versions": self._build_affected_versions_text(detail, affected_entries),
            "affected_products": self._build_affected_products_text(detail, title, description, affected_entries),
            "affected_version_data": serialize_affected_entries(affected_entries) if affected_entries else None,
            "patch_status": "AVAILABLE" if clean_inline_text(detail.get("patch")) else None,
            "remediation": self._build_remediation(detail),
            "source_payload": {
                "list_item": row,
                "detail": detail,
            },
            "source": self.source_name,
            "reference_url": self._build_reference_url(row, detail),
            "published_at": published_at,
            "last_seen_at": last_seen_at,
            "payload": {
                "references": references,
                "list_item": row,
                "detail": detail,
            },
        }

    @staticmethod
    def _normalize_hazard_level(*values) -> str:
        mapping = {
            1: "critical",
            2: "high",
            3: "medium",
            4: "low",
            "1": "critical",
            "2": "high",
            "3": "medium",
            "4": "low",
        }
        for value in values:
            if value in mapping:
                return mapping[value]
        return "unknown"

    @staticmethod
    def _normalize_base_severity(*values) -> str | None:
        mapping = {
            1: "CRITICAL",
            2: "HIGH",
            3: "MEDIUM",
            4: "LOW",
            "1": "CRITICAL",
            "2": "HIGH",
            "3": "MEDIUM",
            "4": "LOW",
        }
        for value in values:
            if value in mapping:
                return mapping[value]
        return None

    def _build_affected_entries(self, detail: dict, title: str, description: str) -> list[dict]:
        entries = []
        seen = set()

        for block in [
            detail.get("affectedProduct"),
            detail.get("affectedSystem"),
            guess_affected_products(title, description),
            clean_inline_text(detail.get("affectedVendor")),
        ]:
            for raw_line in str(block or "").splitlines():
                line = clean_inline_text(raw_line)
                if not line:
                    continue
                entry = build_entry_from_simple_range(line) or build_product_only_entry(line)
                if not entry:
                    continue
                marker = (
                    entry.get("display_label"),
                    entry.get("version_exact"),
                    entry.get("version_start_including"),
                    entry.get("version_start_excluding"),
                    entry.get("version_end_including"),
                    entry.get("version_end_excluding"),
                )
                if marker in seen:
                    continue
                seen.add(marker)
                entries.append(entry)

        return entries

    def _build_affected_versions_text(self, detail: dict, entries: list[dict]) -> str | None:
        text = build_affected_versions_text(entries)
        if text:
            return text
        fallback_lines = collect_unique_lines(detail.get("affectedProduct"), detail.get("affectedSystem"))
        return "\n".join(fallback_lines) or None

    def _build_affected_products_text(self, detail: dict, title: str, description: str, entries: list[dict]) -> str | None:
        text = build_affected_products_text(entries)
        if text:
            return text
        fallback = collect_unique_lines(
            detail.get("affectedProduct"),
            detail.get("affectedSystem"),
            detail.get("affectedVendor"),
            guess_affected_products(title, description),
        )
        return "\n".join(fallback) or None

    @staticmethod
    def _build_remediation(detail: dict) -> str:
        patch = clean_text(detail.get("patch"))
        if not patch:
            return ""
        if patch.startswith("http://") or patch.startswith("https://"):
            return f"补丁链接: {patch}"
        return patch

    @staticmethod
    def _build_references(detail: dict) -> list[str]:
        block = detail.get("referUrl")
        if not block:
            return []
        urls = _URL_PATTERN.findall(str(block))
        if urls:
            return collect_unique_lines(*urls)
        return collect_unique_lines(block)

    def _build_reference_url(self, row: dict, detail: dict) -> str:
        identifier = clean_inline_text(row.get("id") or detail.get("id"))
        vuln_type = clean_inline_text(row.get("vulType") or detail.get("vulType") or "0")
        cnnvd_code = clean_inline_text(detail.get("cnnvdCode") or row.get("cnnvdCode"))
        return (
            f"{self.base_url}/home/loophole"
            f"?id={identifier}&vulType={vuln_type}&cnnvdCode={cnnvd_code}"
        )
