from __future__ import annotations

import time

from lxml import html
from requests import RequestException

from seceventmonitor.models import Vulnerability
from seceventmonitor.services.http_client import build_session
from seceventmonitor.services.collectors.base import BaseCollector
from seceventmonitor.services.collectors.helpers import (
    BROWSER_HEADERS,
    clean_inline_text,
    extract_cve_id,
    guess_affected_products,
    normalize_severity,
    normalize_url,
    parse_datetime_value,
    resolve_since,
)

class SeebugCollector(BaseCollector):
    source_name = "Seebug漏洞库"
    base_url = "https://www.seebug.org"
    list_url = "https://www.seebug.org/vuldb/vulnerabilities"
    page_size = 20
    max_pages = 20
    request_interval_seconds = 0.0

    def __init__(self, settings=None, session=None):
        super().__init__(settings=settings, session=session)
        self._last_request_monotonic = None

    def default_headers(self):
        return {
            **BROWSER_HEADERS,
            "Referer": f"{self.base_url}/",
        }

    def fetch(self, since=None, limit=None, progress_callback=None):
        since = resolve_since(since, fallback_days=120)
        records = []
        total_pages = None

        page_index = 1
        while self.max_pages <= 0 or page_index <= self.max_pages:
            _, rows, detected_total_pages = self.fetch_list_page(page_index)
            if not rows:
                break
            if total_pages is None and detected_total_pages:
                total_pages = detected_total_pages

            all_before_since = True
            should_stop = False
            existing_keys = self._load_existing_vulnerability_keys(rows)
            for row in rows:
                published_at = parse_datetime_value("".join(row.xpath("./td[2]//text()")))
                if published_at is None or published_at >= since:
                    all_before_since = False
                if published_at is not None and published_at < since:
                    continue
                if self._build_vuln_key(row) in existing_keys:
                    should_stop = True
                    break
                records.append(self._parse_row(row, published_at))
                if limit is not None and len(records) >= limit:
                    return records

            if progress_callback:
                total_results = total_pages * self.page_size if total_pages else None
                progress_callback(
                    page_index=page_index,
                    page_size=len(rows),
                    fetched_count=len(records),
                    total_results=total_results,
                )
            if should_stop or all_before_since:
                break
            if total_pages is not None and page_index >= total_pages:
                break
            page_index += 1

        return records

    def fetch_list_page(self, page_index: int):
        last_document = None
        last_rows = []
        for _ in range(3):
            response = self._request_page(self.list_url, params={"page": page_index})
            document = html.fromstring(response.content)
            rows = document.xpath("//table[contains(@class, 'sebug-table')]//tbody/tr")
            last_document = document
            last_rows = rows
            if rows:
                return document, rows, self._extract_total_pages(document)
            time.sleep(1.0)
        return last_document, last_rows, self._extract_total_pages(last_document) if last_document is not None else None

    def _extract_total_pages(self, document) -> int | None:
        values = []
        for item in document.xpath("//ul[contains(@class, 'pagination')]//text()"):
            text = clean_inline_text(item)
            if text.isdigit():
                values.append(int(text))
        return max(values) if values else None

    def _load_existing_vulnerability_keys(self, rows) -> set[str]:
        vuln_keys = [self._build_vuln_key(row) for row in rows if self._build_vuln_key(row)]
        if not vuln_keys:
            return set()
        items = Vulnerability.query.filter(Vulnerability.vuln_key.in_(vuln_keys)).all()
        return {item.vuln_key for item in items}

    def _build_vuln_key(self, row) -> str:
        value = clean_inline_text("".join(row.xpath("./td[1]//a/text()")))
        return f"seebug:{value.lower()}" if value else ""

    def _parse_row(self, row, published_at):
        relative_href = clean_inline_text("".join(row.xpath("./td[1]//a/@href")))
        detail_url = normalize_url(self.base_url, relative_href)
        vuln_key = clean_inline_text("".join(row.xpath("./td[1]//a/text()")))
        title = clean_inline_text("".join(row.xpath("./td[4]//a/text()")))
        severity = normalize_severity("".join(row.xpath("./td[3]//div/@data-original-title")))
        cve_id = extract_cve_id(" ".join(row.xpath("./td[5]//*[@data-original-title]/@data-original-title")), title)
        has_detail = "有详情" in " ".join(row.xpath("./td[5]//*[@data-original-title]/@data-original-title"))

        description = title
        remediation = ""
        if has_detail and detail_url:
            try:
                detail_payload = self._fetch_detail(detail_url)
            except RequestException:
                detail_payload = None
            else:
                description = detail_payload["description"] or description
                remediation = detail_payload["remediation"]

        return {
            "vuln_key": f"seebug:{vuln_key.lower()}",
            "cve_id": cve_id,
            "title": title,
            "description": description,
            "description_lang": "zh",
            "severity": severity,
            "affected_versions": None,
            "affected_products": guess_affected_products(title, description),
            "affected_version_data": None,
            "remediation": remediation,
            "source": self.source_name,
            "reference_url": detail_url,
            "published_at": published_at,
            "last_seen_at": published_at,
            "payload": {
                "detail_available": has_detail,
                "detail_url": detail_url,
            },
        }

    def _fetch_detail(self, detail_url: str):
        response = self._request_page(detail_url)
        response.raise_for_status()
        document = html.fromstring(response.content)
        description = clean_inline_text("".join(document.xpath("//meta[@name='description']/@content")))
        if description.startswith("漏洞概要："):
            description = description.split("：", 1)[1].strip()

        remediation = clean_inline_text(
            "".join(
                document.xpath(
                    "string((//h2[normalize-space()='解决方案' or normalize-space()='解决办法'])[1]/following::div[contains(@class, 'solution-txt')][1])"
                )
            )
        )
        if remediation == "登录后查看":
            remediation = ""
        return {
            "description": description,
            "remediation": remediation,
        }

    def _sleep_before_request(self):
        if self._last_request_monotonic is None:
            return
        elapsed = time.monotonic() - self._last_request_monotonic
        remaining = self.request_interval_seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)

    def _request_page(self, url: str, *, params: dict | None = None):
        self._sleep_before_request()
        response = self.session.get(url, params=params, timeout=self.timeout)
        self._last_request_monotonic = time.monotonic()
        if response.status_code != 403:
            return response

        fallback_session = build_session(
            proxy_url=(self.settings.get("http_proxy") or "").strip(),
            headers=self.default_headers(),
        )
        try:
            response = fallback_session.get(url, params=params, timeout=self.timeout)
        finally:
            fallback_session.close()
        self._last_request_monotonic = time.monotonic()
        return response
