import math
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_
from sqlalchemy.orm import load_only

from seceventmonitor.extensions import db
from seceventmonitor.models import (
    KevCatalogEntry,
    PushConfig,
    SyncJobLog,
    TranslationApiConfig,
    Vulnerability,
    VulnerabilityEvent,
    WatchRule,
)
from seceventmonitor.services.collectors import list_supported_vulnerability_sources
from seceventmonitor.services import settings as settings_service
from seceventmonitor.utils.affected_versions import deserialize_affected_entries, matches_affected_filters
from seceventmonitor.utils.timezone import format_datetime

KEV_SOURCE_LABEL = "CISA KEV"
VULNERABILITY_LIST_COLUMNS = (
    Vulnerability.id,
    Vulnerability.vuln_key,
    Vulnerability.cve_id,
    Vulnerability.description,
    Vulnerability.translated_description,
    Vulnerability.severity,
    Vulnerability.source,
    Vulnerability.status,
    Vulnerability.last_seen_at,
    Vulnerability.created_at,
)
VULNERABILITY_AFFECTED_FILTER_COLUMNS = (
    *VULNERABILITY_LIST_COLUMNS,
    Vulnerability.title,
    Vulnerability.remediation,
    Vulnerability.affected_versions,
    Vulnerability.affected_products,
    Vulnerability.affected_version_data,
)


def get_overview():
    timezone_name = settings_service.get_timezone_name()
    recent_cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=24)
    source_summaries = []
    source_rows = (
        db.session.query(
            Vulnerability.source,
            func.count(Vulnerability.id),
            func.max(Vulnerability.last_seen_at),
        )
        .filter(Vulnerability.source.isnot(None))
        .group_by(Vulnerability.source)
        .order_by(func.count(Vulnerability.id).desc(), Vulnerability.source.asc())
        .all()
    )
    for source, count, latest_seen_at in source_rows:
        normalized_source = str(source or "").strip()
        lowered_source = normalized_source.lower()
        if not normalized_source or lowered_source == "manual" or lowered_source.startswith("github"):
            continue
        if lowered_source in {"阿里云漏洞库", "aliyun_avd"}:
            continue
        source_summaries.append(
            {
                "source": normalized_source,
                "count": count,
                "latest_seen_at": format_datetime(latest_seen_at, timezone_name) or "-",
            }
        )

    return {
        "vulnerability_count": Vulnerability.query.count(),
        "new_event_count_24h": VulnerabilityEvent.query.filter(
            VulnerabilityEvent.event_type == "new",
            VulnerabilityEvent.created_at >= recent_cutoff,
        ).count(),
        "updated_event_count_24h": VulnerabilityEvent.query.filter(
            VulnerabilityEvent.event_type == "updated",
            VulnerabilityEvent.created_at >= recent_cutoff,
        ).count(),
        "enabled_push_config_count": PushConfig.query.filter_by(enabled=True).count(),
        "enabled_translation_api_count": TranslationApiConfig.query.filter_by(enabled=True).count(),
        "kev_catalog_count": KevCatalogEntry.query.count(),
        "active_sync_job_count": SyncJobLog.query.filter(SyncJobLog.status.in_(("queued", "running"))).count(),
        "source_summaries": source_summaries,
        "latest_sync_jobs": [
            item.to_dict(timezone_name=timezone_name)
            for item in SyncJobLog.query.order_by(SyncJobLog.created_at.desc()).limit(10).all()
        ],
    }


def list_vulnerabilities(limit=50):
    timezone_name = settings_service.get_timezone_name()
    return [
        item.to_dict(timezone_name=timezone_name)
        for item in Vulnerability.query.order_by(Vulnerability.created_at.desc()).limit(limit).all()
    ]


def list_vulnerabilities_paginated(
    page=1,
    page_size=10,
    keyword="",
    severity=None,
    source="all",
    status="all",
    affected_product="",
    affected_version="",
):
    timezone_name = settings_service.get_timezone_name()
    page = max(int(page or 1), 1)
    page_size = min(max(int(page_size or 20), 1), 100)
    keyword = (keyword or "").strip().lower()
    severities = _normalize_multi_values(severity)
    source_value = (source or "all").strip()
    source = source_value.lower()
    status = (status or "all").strip().lower()
    affected_product = (affected_product or "").strip().lower()
    affected_version = (affected_version or "").strip()

    query = Vulnerability.query

    if keyword:
        pattern = f"%{keyword}%"
        query = query.filter(
            or_(
                func.lower(Vulnerability.cve_id).like(pattern),
                func.lower(Vulnerability.title).like(pattern),
                func.lower(Vulnerability.description).like(pattern),
                func.lower(func.coalesce(Vulnerability.translated_description, "")).like(pattern),
                func.lower(func.coalesce(Vulnerability.remediation, "")).like(pattern),
                func.lower(func.coalesce(Vulnerability.translated_remediation, "")).like(pattern),
                func.lower(Vulnerability.reference_url).like(pattern),
            )
        )
    if severities:
        query = query.filter(Vulnerability.severity.in_(severities))
    if source == KEV_SOURCE_LABEL.lower():
        query = query.filter(
            func.upper(Vulnerability.cve_id).in_(db.session.query(KevCatalogEntry.cve_id))
        ).filter(
            Vulnerability.source == "NVD"
        )
    elif source != "all":
        query = query.filter(Vulnerability.source == source_value)
    if status != "all":
        query = query.filter(Vulnerability.status == status)
    if affected_product:
        product_pattern = f"%{affected_product}%"
        query = query.filter(
            func.lower(
                func.coalesce(
                    Vulnerability.affected_products,
                    Vulnerability.affected_versions,
                    "",
                )
            ).like(product_pattern)
        )

    uses_advanced_affected_filter = bool(affected_product or affected_version)
    ordered_query = query.order_by(Vulnerability.created_at.desc())

    if uses_advanced_affected_filter:
        candidates = ordered_query.options(load_only(*VULNERABILITY_AFFECTED_FILTER_COLUMNS)).all()
        filtered_items = [
            item
            for item in candidates
            if _matches_affected_search(
                item,
                affected_product=affected_product,
                affected_version=affected_version,
            )
        ]
        total = len(filtered_items)
        total_pages = max(1, math.ceil(total / page_size)) if total else 1
        page = min(page, total_pages)
        offset = (page - 1) * page_size
        items = filtered_items[offset : offset + page_size]
    else:
        total = query.count()
        total_pages = max(1, math.ceil(total / page_size)) if total else 1
        page = min(page, total_pages)
        offset = (page - 1) * page_size
        items = ordered_query.options(load_only(*VULNERABILITY_LIST_COLUMNS)).offset(offset).limit(page_size).all()

    return {
        "items": [_serialize_vulnerability_list_item(item, timezone_name=timezone_name) for item in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }


def get_vulnerability_filter_options():
    existing_sources = [
        row[0]
        for row in db.session.query(Vulnerability.source)
        .filter(Vulnerability.source.isnot(None))
        .distinct()
        .order_by(Vulnerability.source.asc())
        .all()
        if row[0]
        and not str(row[0]).lower().startswith("github")
        and str(row[0]).strip().lower() != "manual"
        and str(row[0]).strip().lower() not in {"阿里云漏洞库", "aliyun_avd"}
    ]
    sources = []
    seen_sources = set()
    for item in [*list_supported_vulnerability_sources(), *existing_sources]:
        normalized = str(item or "").strip()
        lowered = normalized.lower()
        if not normalized:
            continue
        if lowered.startswith("github") or lowered in {"manual", "阿里云漏洞库", "aliyun_avd"}:
            continue
        if lowered in seen_sources:
            continue
        seen_sources.add(lowered)
        sources.append(normalized)
    if KEV_SOURCE_LABEL.lower() not in seen_sources:
        sources.append(KEV_SOURCE_LABEL)

    status_values = [
        row[0]
        for row in db.session.query(Vulnerability.status)
        .filter(Vulnerability.status.isnot(None))
        .distinct()
        .order_by(Vulnerability.status.asc())
        .all()
        if row[0]
    ]
    statuses = []
    for item in ["new", "updated", *status_values]:
        if item and item not in statuses:
            statuses.append(item)
    severities = ["critical", "high", "medium", "low", "unknown"]
    return {
        "sources": sources,
        "statuses": statuses,
        "severities": severities,
    }


def list_rules():
    timezone_name = settings_service.get_timezone_name()
    return [item.to_dict(timezone_name=timezone_name) for item in WatchRule.query.order_by(WatchRule.created_at.desc()).all()]


def create_rule(name: str, rule_type: str, target: str, description: str = "", enabled: bool = True):
    name = (name or "").strip()
    rule_type = (rule_type or "").strip()
    target = (target or "").strip()
    description = (description or "").strip()
    enabled = bool(enabled)

    if not name or not rule_type or not target:
        raise ValueError("规则名称、类型和目标不能为空")

    rule = WatchRule(
        name=name,
        rule_type=rule_type,
        target=target,
        description=description,
        enabled=enabled,
    )
    db.session.add(rule)
    db.session.commit()
    return rule.to_dict(timezone_name=settings_service.get_timezone_name())


def update_rule(rule_id: int, **payload):
    rule = db.session.get(WatchRule, rule_id)
    if rule is None:
        raise ValueError("规则不存在")

    for field in ["name", "rule_type", "target", "description"]:
        if field in payload:
            setattr(rule, field, (payload.get(field) or "").strip())
    if "enabled" in payload:
        rule.enabled = bool(payload["enabled"])

    db.session.commit()
    return rule.to_dict(timezone_name=settings_service.get_timezone_name())


def delete_rule(rule_id: int):
    rule = db.session.get(WatchRule, rule_id)
    if rule is None:
        raise ValueError("规则不存在")
    db.session.delete(rule)
    db.session.commit()


def list_sync_jobs(limit=20):
    timezone_name = settings_service.get_timezone_name()
    return [
        item.to_dict(timezone_name=timezone_name)
        for item in SyncJobLog.query.order_by(SyncJobLog.created_at.desc()).limit(limit).all()
    ]


def list_sync_jobs_paginated(page=1, page_size=10):
    timezone_name = settings_service.get_timezone_name()
    page = max(int(page or 1), 1)
    page_size = min(max(int(page_size or 10), 1), 100)

    query = SyncJobLog.query.order_by(SyncJobLog.created_at.desc())
    total = query.count()
    total_pages = max(1, math.ceil(total / page_size)) if total else 1
    page = min(page, total_pages)
    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()

    return {
        "items": [item.to_dict(timezone_name=timezone_name) for item in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }


def _matches_affected_search(vulnerability, *, affected_product="", affected_version=""):
    entries = deserialize_affected_entries(
        vulnerability.affected_version_data,
        vulnerability.affected_versions or "",
    )
    if matches_affected_filters(
        entries,
        product_keyword=affected_product,
        version_keyword=affected_version,
    ):
        return True

    fallback_text = "\n".join(
        [
            vulnerability.affected_products or "",
            vulnerability.affected_versions or "",
            vulnerability.title or "",
            vulnerability.description or "",
            vulnerability.remediation or "",
        ]
    ).lower()
    product_keyword = (affected_product or "").strip().lower()
    version_keyword = (affected_version or "").strip().lower()
    if product_keyword and product_keyword not in fallback_text:
        return False
    if version_keyword and version_keyword not in fallback_text:
        return False
    return bool(product_keyword or version_keyword)


def _serialize_vulnerability_list_item(vulnerability, *, timezone_name: str | None = None):
    return {
        "id": vulnerability.id,
        "vuln_key": vulnerability.vuln_key,
        "cve_id": vulnerability.cve_id,
        "display_identifier": vulnerability.display_identifier,
        "source_identifier": vulnerability.source_identifier,
        "description": vulnerability.description,
        "translated_description": vulnerability.translated_description,
        "severity": vulnerability.severity,
        "source": vulnerability.source,
        "status": vulnerability.status,
        "last_seen_at": format_datetime(vulnerability.last_seen_at, timezone_name),
        "created_at": format_datetime(vulnerability.created_at, timezone_name),
    }


def _normalize_multi_values(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = [value]

    output = []
    seen = set()
    for item in items:
        normalized = (item or "").strip().lower()
        if not normalized or normalized == "all" or normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output
