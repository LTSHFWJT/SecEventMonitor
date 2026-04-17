import logging
import math
import time
from datetime import UTC, datetime, timedelta

from requests import ConnectionError, RequestException, Timeout

from seceventmonitor.services.collectors.base import BaseCollector
from seceventmonitor.utils.affected_versions import (
    build_affected_entry_from_cpe_match,
    build_affected_products_text,
    build_affected_versions_text,
    serialize_affected_entries,
)


logger = logging.getLogger(__name__)


class NvdCollector(BaseCollector):
    source_name = "NVD"
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    timeout = (10, 120)
    max_results_per_page = 2000
    max_retry_attempts = 5
    request_interval_seconds = 6.0
    retry_backoff_base_seconds = 5.0
    retry_backoff_cap_seconds = 60.0
    retryable_status_codes = frozenset({429, 500, 502, 503, 504})

    def __init__(self, settings=None, session=None):
        super().__init__(settings=settings, session=session)
        self._last_request_monotonic = None

    def default_headers(self):
        headers = {}
        api_key = (self.settings.get("nvd_api_key") or "").strip()
        if api_key:
            headers["apiKey"] = api_key
        return headers

    def fetch_page_payload(self, *, params, max_retries=None):
        retry_attempts = max(1, int(max_retries or self.max_retry_attempts))
        last_error = None

        for attempt in range(1, retry_attempts + 1):
            self._sleep_before_request()
            try:
                response = self.session.get(
                    self.api_url,
                    params=params,
                    timeout=self.timeout,
                )
                self._last_request_monotonic = time.monotonic()
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("NVD response payload is not a JSON object")
                return payload
            except ValueError as exc:
                last_error = exc
                if attempt >= retry_attempts:
                    break
                wait_seconds = self._resolve_retry_wait_seconds(attempt)
                logger.warning(
                    "Retry NVD request after invalid JSON: attempt=%s/%s wait=%.1fs params=%s error=%s",
                    attempt,
                    retry_attempts,
                    wait_seconds,
                    params,
                    exc,
                )
                time.sleep(wait_seconds)
            except RequestException as exc:
                last_error = exc
                if not self._is_retryable_request_error(exc) or attempt >= retry_attempts:
                    break
                wait_seconds = self._resolve_retry_wait_seconds(attempt, response=getattr(exc, "response", None))
                logger.warning(
                    "Retry NVD request after transport error: attempt=%s/%s wait=%.1fs params=%s error=%s",
                    attempt,
                    retry_attempts,
                    wait_seconds,
                    params,
                    exc,
                )
                time.sleep(wait_seconds)

        if last_error is not None:
            raise last_error
        raise RuntimeError("NVD request failed without an exception")

    def fetch(self, since=None, limit=None, page_size=None, progress_callback=None):
        now = datetime.now(UTC)
        # On the first sync when there is no checkpoint yet, only backfill the latest 24 hours.
        since = since or (now - timedelta(hours=24))

        items = []
        start_index = 0
        requested_page_size = page_size or self.max_results_per_page
        per_page = max(1, min(int(requested_page_size), self.max_results_per_page))

        while True:
            payload = self.fetch_page_payload(
                params={
                    "lastModStartDate": self.to_utc_iso(since),
                    "lastModEndDate": self.to_utc_iso(now),
                    "resultsPerPage": per_page,
                    "startIndex": start_index,
                },
            )

            vulnerabilities = payload.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for entry in vulnerabilities:
                cve = entry.get("cve") or {}
                if (cve.get("vulnStatus") or "").lower() == "rejected":
                    continue
                items.append(self._normalize_cve(cve))
                if limit is not None and len(items) >= limit:
                    break

            start_index += len(vulnerabilities)
            total_results = payload.get("totalResults", 0)
            if progress_callback:
                progress_callback(
                    page_index=max(1, math.ceil(start_index / per_page)),
                    page_size=per_page,
                    fetched_count=len(items),
                    total_results=total_results,
                )
            if limit is not None and len(items) >= limit:
                break
            if start_index >= total_results:
                break

        return items

    def _normalize_cve(self, cve):
        cve_id = cve.get("id") or ""
        description, description_lang = self._pick_description(cve.get("descriptions") or [])
        metric = self._extract_metric(cve.get("metrics") or {})
        affected_entries = self._extract_affected_entries(cve.get("configurations") or [])
        remediation = self._extract_remediation(cve)

        return {
            "vuln_key": f"nvd:{cve_id}",
            "cve_id": cve_id,
            "title": "",
            "description": description,
            "description_lang": description_lang,
            "severity": metric.get("severity") or "unknown",
            "vuln_status": cve.get("vulnStatus"),
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
            "exploitability_score": metric.get("exploitability_score"),
            "impact_score": metric.get("impact_score"),
            "affected_versions": build_affected_versions_text(affected_entries),
            "affected_products": build_affected_products_text(affected_entries),
            "affected_version_data": serialize_affected_entries(affected_entries),
            "remediation": remediation,
            "source": self.source_name,
            "reference_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published_at": self.parse_datetime(cve.get("published")),
            "last_seen_at": self.parse_datetime(cve.get("lastModified")),
            "payload": {
                "vuln_status": cve.get("vulnStatus"),
                "descriptions": cve.get("descriptions") or [],
                "references": cve.get("references") or [],
                "configurations": cve.get("configurations") or [],
                "vendorComments": cve.get("vendorComments") or [],
                "evaluatorSolution": cve.get("evaluatorSolution"),
                "cisaRequiredAction": cve.get("cisaRequiredAction"),
                "metrics": cve.get("metrics") or {},
                "selected_cvss_version": metric.get("cvss_version"),
            },
        }

    def _pick_description(self, descriptions):
        for item in descriptions:
            if item.get("lang") == "en" and item.get("value"):
                return item["value"].strip(), (item.get("lang") or "").strip().lower() or None
        for item in descriptions:
            if item.get("value"):
                return item["value"].strip(), (item.get("lang") or "").strip().lower() or None
        return "", None

    def _extract_metric(self, metrics):
        metric_order = [
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0"),
        ]
        for key, fallback_version in metric_order:
            entry = self._pick_metric_entry(metrics.get(key) or [])
            if entry is None:
                continue
            cvss_data = entry.get("cvssData") or {}
            base_severity = (
                entry.get("baseSeverity")
                or cvss_data.get("baseSeverity")
                or ""
            )
            return {
                "cvss_version": cvss_data.get("version") or fallback_version,
                "base_score": self._to_float(cvss_data.get("baseScore")),
                "base_severity": base_severity or None,
                "severity": (base_severity or "unknown").lower(),
                "vector_string": cvss_data.get("vectorString") or None,
                "attack_vector": cvss_data.get("attackVector") or None,
                "attack_complexity": cvss_data.get("attackComplexity") or None,
                "attack_requirements": cvss_data.get("attackRequirements") or None,
                "privileges_required": cvss_data.get("privilegesRequired") or None,
                "user_interaction": cvss_data.get("userInteraction") or None,
                "scope": cvss_data.get("scope") or None,
                "confidentiality_impact": (
                    cvss_data.get("confidentialityImpact")
                    or cvss_data.get("vulnConfidentialityImpact")
                    or None
                ),
                "integrity_impact": (
                    cvss_data.get("integrityImpact")
                    or cvss_data.get("vulnIntegrityImpact")
                    or None
                ),
                "availability_impact": (
                    cvss_data.get("availabilityImpact")
                    or cvss_data.get("vulnAvailabilityImpact")
                    or None
                ),
                "exploitability_score": self._to_float(entry.get("exploitabilityScore")),
                "impact_score": self._to_float(entry.get("impactScore")),
            }
        return {"severity": "unknown"}

    def _pick_metric_entry(self, entries):
        if not entries:
            return None
        for entry in entries:
            if (entry.get("type") or "").lower() == "primary":
                return entry
        for entry in entries:
            if (entry.get("source") or "").lower() == "nvd@nist.gov":
                return entry
        return entries[0]

    @staticmethod
    def _to_float(value):
        if value in (None, ""):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _extract_affected_entries(self, configurations):
        entries = []
        seen = set()
        for config in configurations:
            for entry in self._collect_affected_entries(config.get("nodes") or []):
                fingerprint = (
                    entry.get("display_label"),
                    entry.get("version_exact"),
                    entry.get("version_start_including"),
                    entry.get("version_start_excluding"),
                    entry.get("version_end_including"),
                    entry.get("version_end_excluding"),
                )
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                entries.append(entry)
        return entries

    def _collect_affected_entries(self, nodes):
        output = []
        for node in nodes:
            if node.get("negate"):
                continue

            for match in node.get("cpeMatch") or []:
                entry = build_affected_entry_from_cpe_match(match)
                if entry:
                    output.append(entry)

            for child_key in ("children", "nodes"):
                child_nodes = node.get(child_key) or []
                if child_nodes:
                    output.extend(self._collect_affected_entries(child_nodes))

        return output

    def _extract_remediation(self, cve):
        sections = []
        evaluator_solution = (cve.get("evaluatorSolution") or "").strip()
        if evaluator_solution:
            sections.append(f"NVD 解决建议\n{evaluator_solution}")

        vendor_comments = []
        for item in cve.get("vendorComments") or []:
            comment = (item.get("comment") or "").strip()
            if not comment:
                continue
            organization = (item.get("organization") or "").strip()
            if organization:
                vendor_comments.append(f"[{organization}] {comment}")
            else:
                vendor_comments.append(comment)
        if vendor_comments:
            sections.append("厂商备注\n" + "\n".join(vendor_comments))

        cisa_required_action = (cve.get("cisaRequiredAction") or "").strip()
        if cisa_required_action:
            sections.append(f"CISA 要求措施\n{cisa_required_action}")

        return "\n\n".join(sections)

    def _sleep_before_request(self):
        if self._last_request_monotonic is None:
            return
        elapsed = time.monotonic() - self._last_request_monotonic
        remaining = self.request_interval_seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)

    def _resolve_retry_wait_seconds(self, attempt, response=None):
        retry_after = self._parse_retry_after_seconds(response)
        if retry_after is not None:
            return retry_after
        return min(self.retry_backoff_cap_seconds, self.retry_backoff_base_seconds * (2 ** (attempt - 1)))

    @staticmethod
    def _parse_retry_after_seconds(response):
        if response is None:
            return None
        value = (response.headers.get("Retry-After") or "").strip()
        if not value:
            return None
        try:
            return max(float(value), 0.0)
        except (TypeError, ValueError):
            return None

    def _is_retryable_request_error(self, exc):
        response = getattr(exc, "response", None)
        status_code = getattr(response, "status_code", None)
        if status_code in self.retryable_status_codes:
            return True
        return isinstance(exc, (Timeout, ConnectionError))
