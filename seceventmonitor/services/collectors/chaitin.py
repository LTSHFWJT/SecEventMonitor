from __future__ import annotations

import time
from datetime import UTC

from seceventmonitor.models import Vulnerability
from seceventmonitor.services.collectors.base import BaseCollector
from seceventmonitor.services.collectors.helpers import (
    BROWSER_HEADERS,
    clean_inline_text,
    clean_text,
    collect_unique_lines,
    extract_cve_id,
    guess_affected_products,
    normalize_severity,
    parse_datetime_value,
    resolve_since,
)


class ChaitinCollector(BaseCollector):
    source_name = "长亭漏洞库"
    api_url = "https://stack.chaitin.com/api/v2/vuln/list/"
    page_size = 15
    max_pages = 200
    request_interval_seconds = 2.0

    def __init__(self, settings=None, session=None):
        super().__init__(settings=settings, session=session)
        self._last_request_monotonic = None

    def default_headers(self):
        return {
            **BROWSER_HEADERS,
            "Referer": "https://stack.chaitin.com/vuldb/index",
            "Origin": "https://stack.chaitin.com",
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
        threshold = None if full_history else resolve_since(since, fallback_days=30)
        records = []
        offset = 0
        page_index = 0

        while page_index < self.max_pages:
            payload = self._fetch_page_payload(offset)
            data = payload.get("data") or {}
            rows = data.get("list") or []
            if not rows:
                break

            page_index += 1
            all_before_since = threshold is not None
            should_stop = False
            existing_map = self._load_existing_vulnerabilities(rows) if stop_on_existing else {}

            for row in rows:
                published_at = parse_datetime_value(
                    row.get("disclosure_date") or row.get("created_at") or row.get("updated_at")
                )
                last_seen_at = parse_datetime_value(row.get("updated_at") or row.get("created_at"))
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

                records.append(
                    self._normalize_item(
                        row,
                        vuln_key=vuln_key,
                        published_at=published_at,
                        last_seen_at=last_seen_at,
                    )
                )
                if limit is not None and len(records) >= limit:
                    return records[:limit]

            if progress_callback:
                progress_callback(
                    page_index=page_index,
                    page_size=self.page_size,
                    fetched_count=len(records),
                    total_results=data.get("count"),
                )

            if should_stop or (threshold is not None and all_before_since) or len(rows) < self.page_size:
                break

            offset += len(rows)

        return records

    def _fetch_page_payload(self, offset: int) -> dict:
        self._sleep_before_request()
        response = self.session.get(
            self.api_url,
            params={
                "limit": self.page_size,
                "offset": offset,
                "search": "",
            },
            timeout=self.timeout,
        )
        self._last_request_monotonic = time.monotonic()
        response.raise_for_status()
        return response.json()

    def _sleep_before_request(self):
        if self._last_request_monotonic is None:
            return
        elapsed = time.monotonic() - self._last_request_monotonic
        remaining = self.request_interval_seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)

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
    def _build_vuln_key(item) -> str:
        return f"chaitin:{clean_inline_text(item.get('ct_id'))}"

    def _normalize_item(self, item, *, vuln_key: str, published_at=None, last_seen_at=None):
        title = clean_inline_text(item.get("title"))
        description = clean_text(item.get("summary"))
        cve_id = extract_cve_id(item.get("cve_id"), title, description)
        references = self._normalize_references(item.get("references"))
        cvss3 = item.get("cvss3") if isinstance(item.get("cvss3"), dict) else {}
        cvss_metric = self._normalize_cvss3(cvss3, severity=item.get("severity"))

        return {
            "vuln_key": vuln_key,
            "cve_id": cve_id,
            "title": title,
            "description": description,
            "description_lang": "zh",
            "severity": normalize_severity(item.get("severity")),
            "cvss_version": cvss_metric.get("cvss_version"),
            "base_score": cvss_metric.get("base_score"),
            "base_severity": cvss_metric.get("base_severity"),
            "vector_string": cvss_metric.get("vector_string"),
            "attack_vector": cvss_metric.get("attack_vector"),
            "attack_complexity": cvss_metric.get("attack_complexity"),
            "attack_requirements": cvss_metric.get("attack_requirements"),
            "privileges_required": cvss_metric.get("privileges_required"),
            "user_interaction": cvss_metric.get("user_interaction"),
            "scope": cvss_metric.get("scope"),
            "confidentiality_impact": cvss_metric.get("confidentiality_impact"),
            "integrity_impact": cvss_metric.get("integrity_impact"),
            "availability_impact": cvss_metric.get("availability_impact"),
            "affected_versions": None,
            "affected_products": guess_affected_products(title, description),
            "affected_version_data": None,
            "remediation": clean_text(item.get("fix_steps")),
            "source_payload": item,
            "source": self.source_name,
            "reference_url": f"https://stack.chaitin.com/vuldb/detail/{item.get('id')}",
            "published_at": published_at,
            "last_seen_at": last_seen_at or published_at,
            "payload": {
                "references": references,
                "raw": item,
            },
        }

    @staticmethod
    def _normalize_references(value) -> list[str]:
        if isinstance(value, list):
            return collect_unique_lines(*value)
        return collect_unique_lines(value)

    def _normalize_cvss3(self, value: dict, *, severity: str | None = None) -> dict:
        if not value:
            return {
                "cvss_version": None,
                "base_score": None,
                "base_severity": (clean_inline_text(severity).upper() or None),
                "vector_string": None,
                "attack_vector": None,
                "attack_complexity": None,
                "attack_requirements": None,
                "privileges_required": None,
                "user_interaction": None,
                "scope": None,
                "confidentiality_impact": None,
                "integrity_impact": None,
                "availability_impact": None,
            }

        def mapped(mapping: dict[str, str], key: str):
            raw = clean_inline_text(value.get(key)).upper()
            return mapping.get(raw)

        attack_vector = mapped(
            {
                "N": "NETWORK",
                "A": "ADJACENT_NETWORK",
                "L": "LOCAL",
                "P": "PHYSICAL",
            },
            "AV",
        )
        attack_complexity = mapped({"L": "LOW", "H": "HIGH"}, "AC")
        attack_requirements = mapped({"N": "NONE", "P": "PRESENT"}, "AR")
        privileges_required = mapped({"N": "NONE", "L": "LOW", "H": "HIGH"}, "PR")
        user_interaction = mapped({"N": "NONE", "R": "REQUIRED", "P": "PASSIVE", "A": "ACTIVE"}, "UI")
        scope = mapped({"U": "UNCHANGED", "C": "CHANGED"}, "S")
        confidentiality_impact = mapped({"N": "NONE", "L": "LOW", "H": "HIGH"}, "C")
        integrity_impact = mapped({"N": "NONE", "L": "LOW", "H": "HIGH"}, "I")
        availability_impact = mapped({"N": "NONE", "L": "LOW", "H": "HIGH"}, "A")

        vector_parts = []
        for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
            raw = clean_inline_text(value.get(key)).upper()
            if raw and raw != "X":
                vector_parts.append(f"{key}:{raw}")

        return {
            "cvss_version": "3.1",
            "base_score": None,
            "base_severity": clean_inline_text(severity).upper() or None,
            "vector_string": f"CVSS:3.1/{'/'.join(vector_parts)}" if vector_parts else None,
            "attack_vector": attack_vector,
            "attack_complexity": attack_complexity,
            "attack_requirements": attack_requirements,
            "privileges_required": privileges_required,
            "user_interaction": user_interaction,
            "scope": scope,
            "confidentiality_impact": confidentiality_impact,
            "integrity_impact": integrity_impact,
            "availability_impact": availability_impact,
        }
