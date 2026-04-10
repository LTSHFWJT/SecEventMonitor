from __future__ import annotations

import logging
import time
from datetime import UTC

from requests import RequestException

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
from seceventmonitor.utils.affected_versions import (
    build_affected_products_text,
    build_affected_versions_text,
    serialize_affected_entries,
)


logger = logging.getLogger(__name__)


class OscsCollector(BaseCollector):
    source_name = "OSCS开源安全情报预警"
    list_url = "https://www.oscs1024.com/oscs/v1/intelligence/list"
    detail_url_template = "https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{mps}"
    legacy_detail_url = "https://www.oscs1024.com/oscs/v1/vdb/info"
    page_size = 50
    max_pages = 200
    request_interval_seconds = 2.0

    def __init__(self, settings=None, session=None):
        super().__init__(settings=settings, session=session)
        self._last_request_monotonic = None

    def default_headers(self):
        return {
            **BROWSER_HEADERS,
            "Referer": "https://www.oscs1024.com/cm",
            "Origin": "https://www.oscs1024.com",
            "Content-Type": "application/json",
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

        for page_index in range(1, self.max_pages + 1):
            payload = self._fetch_list_payload(page_index)
            data = payload.get("data") or {}
            rows = data.get("data") or []
            total_results = data.get("total")
            if not rows:
                break

            all_before_since = threshold is not None
            should_stop = False
            existing_map = self._load_existing_vulnerabilities(rows) if stop_on_existing else {}

            for item in rows:
                compare_time = parse_datetime_value(
                    item.get("public_time") or item.get("updated_at") or item.get("created_at")
                )
                if threshold is not None:
                    if compare_time is None or compare_time >= threshold:
                        all_before_since = False
                    if compare_time is not None and compare_time < threshold:
                        continue

                vuln_key = self._build_vuln_key(item)
                existing = existing_map.get(vuln_key)
                if stop_on_existing and self._is_existing_up_to_date(existing, compare_time):
                    should_stop = True
                    break

                mps = item.get("mps")
                try:
                    detail = self._fetch_detail(mps)
                except RequestException as exc:
                    if self._should_skip_detail_error(exc):
                        logger.warning("Skip OSCS item due to detail fetch error: mps=%s error=%s", mps, exc)
                        continue
                    raise

                try:
                    legacy_detail = self._fetch_legacy_detail(mps)
                except RequestException as exc:
                    logger.warning("Ignore OSCS legacy detail fetch error: mps=%s error=%s", mps, exc)
                    legacy_detail = {}

                records.append(self._normalize_item(item, detail, legacy_detail))
                if limit is not None and len(records) >= limit:
                    return records[:limit]

            if progress_callback:
                progress_callback(
                    page_index=page_index,
                    page_size=self.page_size,
                    fetched_count=len(records),
                    total_results=total_results,
                )

            if should_stop or (threshold is not None and all_before_since) or len(rows) < self.page_size:
                break

        return records

    def _fetch_list_payload(self, page: int) -> dict:
        self._sleep_before_request()
        response = self.session.post(
            self.list_url,
            json={"page": page, "per_page": self.page_size},
            timeout=self.timeout,
        )
        self._last_request_monotonic = time.monotonic()
        response.raise_for_status()
        return response.json()

    def _fetch_detail(self, mps: str | None) -> dict:
        target_mps = clean_inline_text(mps)
        if not target_mps:
            return {}
        target = self.detail_url_template.format(mps=target_mps)
        self._sleep_before_request()
        response = self.session.get(target, timeout=self.timeout)
        self._last_request_monotonic = time.monotonic()
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict):
            return payload
        return {}

    def _fetch_legacy_detail(self, mps: str | None) -> dict:
        vuln_no = clean_inline_text(mps)
        if not vuln_no:
            return {}
        self._sleep_before_request()
        response = self.session.post(
            self.legacy_detail_url,
            json={"vuln_no": vuln_no},
            timeout=self.timeout,
        )
        self._last_request_monotonic = time.monotonic()
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return {}
        data = payload.get("data")
        if isinstance(data, list) and data:
            first_item = data[0]
            return first_item if isinstance(first_item, dict) else {}
        if isinstance(data, dict):
            return data
        return {}

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
        return bool(status_code and int(status_code) >= 500)

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
        return f"oscs:{clean_inline_text(item.get('mps'))}"

    def _normalize_item(self, item, detail, legacy_detail):
        title = clean_inline_text(
            detail.get("title") or legacy_detail.get("title") or legacy_detail.get("vuln_title") or item.get("title")
        )
        description = clean_text(detail.get("description") or legacy_detail.get("description"))
        cve_id = extract_cve_id(
            detail.get("cve_id"),
            legacy_detail.get("cve_id"),
            legacy_detail.get("vuln_cve_id"),
            title,
            description,
        )
        metric = self._select_cvss_metric(detail, legacy_detail)
        affected_entries = self._build_affected_entries(detail.get("effects") or legacy_detail.get("effect") or [])
        remediation_lines = self._build_remediation_lines(detail, legacy_detail)
        references = self._build_references(detail, legacy_detail)

        affected_versions = build_affected_versions_text(affected_entries)
        affected_products = build_affected_products_text(affected_entries) or guess_affected_products(title, description)
        published_at = parse_datetime_value(
            detail.get("published_time") or legacy_detail.get("publish_time") or item.get("public_time")
        )
        last_seen_at = parse_datetime_value(
            detail.get("last_modified_time")
            or legacy_detail.get("last_modified_time")
            or item.get("updated_at")
            or item.get("created_at")
            or legacy_detail.get("publish_time")
        )
        if last_seen_at is None:
            last_seen_at = published_at

        return {
            "vuln_key": self._build_vuln_key(item),
            "cve_id": cve_id,
            "title": title,
            "description": description,
            "description_lang": "zh",
            "severity": normalize_severity(detail.get("level") or item.get("level")),
            "cvss_version": metric.get("cvss_version"),
            "base_score": metric.get("base_score"),
            "base_severity": metric.get("base_severity"),
            "vector_string": metric.get("vector_string"),
            "attack_vector": metric.get("attack_vector"),
            "attack_complexity": metric.get("attack_complexity"),
            "attack_requirements": metric.get("attack_requirements"),
            "privileges_required": metric.get("privileges_required"),
            "user_interaction": metric.get("user_interaction"),
            "scope": metric.get("scope"),
            "confidentiality_impact": metric.get("confidentiality_impact"),
            "integrity_impact": metric.get("integrity_impact"),
            "availability_impact": metric.get("availability_impact"),
            "affected_versions": affected_versions or None,
            "affected_products": affected_products or None,
            "affected_version_data": serialize_affected_entries(affected_entries) if affected_entries else None,
            "remediation": "\n".join(remediation_lines),
            "source_payload": {
                "list_item": item,
                "detail": detail,
                "legacy_detail": legacy_detail,
            },
            "source": self.source_name,
            "reference_url": clean_inline_text(item.get("url")) or f"https://www.oscs1024.com/hd/{item.get('mps')}",
            "published_at": published_at,
            "last_seen_at": last_seen_at,
            "payload": {
                "references": references,
                "list_item": item,
                "detail": detail,
                "legacy_detail": legacy_detail,
            },
        }

    @staticmethod
    def _select_cvss_metric(detail: dict, legacy_detail: dict | None = None) -> dict:
        cvss = detail.get("cvss") if isinstance(detail.get("cvss"), dict) else {}
        selected = None
        version = None
        for key, resolved_version in (("cvssv31", "3.1"), ("cvssv3", "3.0"), ("cvssv2", "2.0")):
            items = cvss.get(key)
            if isinstance(items, list) and items:
                selected = items[0]
                version = resolved_version
                break

        legacy_detail = legacy_detail or {}
        vector_string = clean_inline_text(
            (selected or {}).get("vector") or detail.get("cvss_vector") or legacy_detail.get("cvss_vector")
        ) or None
        attack_vector = OscsCollector._parse_vector_field(vector_string, "AV")
        return {
            "cvss_version": version,
            "base_score": (selected or {}).get("base_score") or detail.get("cvss_score") or legacy_detail.get("cvss_score"),
            "base_severity": clean_inline_text(
                (selected or {}).get("severity") or detail.get("level") or legacy_detail.get("level")
            ).upper()
            or None,
            "vector_string": vector_string,
            "attack_vector": attack_vector or clean_inline_text(legacy_detail.get("attack_vector")).upper() or None,
            "attack_complexity": OscsCollector._parse_vector_field(vector_string, "AC"),
            "attack_requirements": OscsCollector._parse_vector_field(vector_string, "AT"),
            "privileges_required": OscsCollector._parse_vector_field(vector_string, "PR"),
            "user_interaction": OscsCollector._parse_vector_field(vector_string, "UI"),
            "scope": OscsCollector._parse_vector_field(vector_string, "S"),
            "confidentiality_impact": OscsCollector._parse_vector_field(vector_string, "C"),
            "integrity_impact": OscsCollector._parse_vector_field(vector_string, "I"),
            "availability_impact": OscsCollector._parse_vector_field(vector_string, "A"),
        }

    @staticmethod
    def _parse_vector_field(vector_string: str | None, key: str) -> str | None:
        text = clean_inline_text(vector_string)
        if not text:
            return None
        mapping = {
            "AV": {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"},
            "AC": {"L": "LOW", "H": "HIGH"},
            "AT": {"N": "NONE", "P": "PRESENT"},
            "PR": {"N": "NONE", "L": "LOW", "H": "HIGH"},
            "UI": {"N": "NONE", "R": "REQUIRED", "P": "PASSIVE", "A": "ACTIVE"},
            "S": {"U": "UNCHANGED", "C": "CHANGED"},
            "C": {"N": "NONE", "L": "LOW", "H": "HIGH"},
            "I": {"N": "NONE", "L": "LOW", "H": "HIGH"},
            "A": {"N": "NONE", "L": "LOW", "H": "HIGH"},
        }
        for part in text.split("/"):
            if ":" not in part:
                continue
            current_key, raw_value = part.split(":", 1)
            if current_key != key:
                continue
            return mapping.get(key, {}).get(raw_value.upper(), raw_value.upper())
        return None

    def _build_affected_entries(self, effects):
        entries = []
        for effect in effects:
            if not isinstance(effect, dict):
                continue
            product = clean_inline_text(effect.get("comp_name") or effect.get("name"))
            if not product:
                continue
            versions = effect.get("versions") or []
            if not versions:
                entry = self._make_entry(product)
                affected_version = clean_inline_text(effect.get("affected_version"))
                min_fixed_version = clean_inline_text(effect.get("min_fixed_version"))
                if affected_version:
                    self._apply_affected_version(entry, affected_version)
                if (
                    min_fixed_version
                    and not entry["version_end_including"]
                    and not entry["version_end_excluding"]
                    and affected_version in {"", "影响所有版本"}
                ):
                    entry["version_end_excluding"] = min_fixed_version
                entries.append(entry)
                continue
            for version in versions:
                entry = self._make_entry(product)
                affected_version = clean_inline_text(version.get("affected_version"))
                min_fixed_version = clean_inline_text(version.get("min_fixed_version"))
                if affected_version:
                    self._apply_affected_version(entry, affected_version)
                if (
                    min_fixed_version
                    and not entry["version_end_including"]
                    and not entry["version_end_excluding"]
                    and affected_version in {"", "影响所有版本"}
                ):
                    entry["version_end_excluding"] = min_fixed_version
                entries.append(entry)
        return entries

    @staticmethod
    def _make_entry(product: str) -> dict:
        return {
            "part": "a",
            "part_label": "应用",
            "vendor": "",
            "product": product,
            "product_label": product,
            "display_label": f"[应用] {product}",
            "version_exact": None,
            "version_start_including": None,
            "version_start_excluding": None,
            "version_end_including": None,
            "version_end_excluding": None,
            "criteria": "",
        }

    @staticmethod
    def _apply_affected_version(entry: dict, affected_version: str) -> None:
        text = clean_inline_text(affected_version)
        if not text or text == "影响所有版本":
            return
        if text.startswith("(-∞,") and text.endswith(")"):
            entry["version_end_excluding"] = clean_inline_text(text[4:-1]) or None
            return
        if text.startswith("(-∞,") and text.endswith("]"):
            entry["version_end_including"] = clean_inline_text(text[4:-1]) or None
            return
        if text.startswith("[") and text.endswith(")"):
            start_value, _, end_value = text[1:-1].partition(",")
            entry["version_start_including"] = clean_inline_text(start_value) or None
            entry["version_end_excluding"] = clean_inline_text(end_value) or None
            return
        if text.startswith("(") and text.endswith(")"):
            start_value, _, end_value = text[1:-1].partition(",")
            entry["version_start_excluding"] = clean_inline_text(start_value) or None
            entry["version_end_excluding"] = clean_inline_text(end_value) or None
            return
        if text.startswith("[") and text.endswith("]"):
            start_value, _, end_value = text[1:-1].partition(",")
            entry["version_start_including"] = clean_inline_text(start_value) or None
            entry["version_end_including"] = clean_inline_text(end_value) or None
            return
        entry["version_exact"] = text

    def _build_remediation_lines(self, detail: dict, legacy_detail: dict) -> list[str]:
        return self._collect_meaningful_lines(
            legacy_detail.get("soulution_data"),
            [
                solution.get("description")
                for effect in legacy_detail.get("effect") or []
                if isinstance(effect, dict)
                for solution in effect.get("solutions") or []
                if isinstance(solution, dict)
            ],
            legacy_detail.get("patch"),
            legacy_detail.get("vuln_suggest"),
            [
                solution.get("description")
                for effect in detail.get("effects") or []
                if isinstance(effect, dict)
                for version in effect.get("versions") or []
                if isinstance(version, dict)
                for solution in version.get("solutions") or []
                if isinstance(solution, dict)
            ],
            detail.get("fix_suggestion"),
        )

    def _build_references(self, detail: dict, legacy_detail: dict) -> list[str]:
        return collect_unique_lines(
            *[
                self._reference_to_text(reference)
                for reference in (detail.get("reference_url_list") or []) + (legacy_detail.get("references") or [])
            ]
        )

    @classmethod
    def _collect_meaningful_lines(cls, *values) -> list[str]:
        output = []
        seen = set()
        for value in values:
            for text in cls._flatten_text_values(value):
                for raw_line in str(text or "").splitlines():
                    line = clean_inline_text(raw_line.lstrip("•").lstrip("-"))
                    lowered = line.lower()
                    if not line or lowered in seen or cls._is_placeholder_remediation(line):
                        continue
                    seen.add(lowered)
                    output.append(line)
        return output

    @classmethod
    def _flatten_text_values(cls, value) -> list[str]:
        if value in (None, ""):
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [value.get("description") or value.get("name") or value.get("url") or ""]
        if isinstance(value, (list, tuple, set)):
            output = []
            for item in value:
                output.extend(cls._flatten_text_values(item))
            return output
        return [str(value)]

    @staticmethod
    def _reference_to_text(value) -> str:
        if isinstance(value, dict):
            return clean_inline_text(value.get("url") or value.get("name"))
        return clean_inline_text(value)

    @staticmethod
    def _is_placeholder_remediation(value: str | None) -> bool:
        text = clean_inline_text(value).lower()
        return text in {
            "",
            "-",
            "--",
            "/",
            "n/a",
            "na",
            "none",
            "recommend",
            "recommended",
            "暂无",
            "无",
            "未知",
            "待补充",
        }
