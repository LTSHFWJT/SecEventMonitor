import math
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import load_only

from seceventmonitor.extensions import db
from seceventmonitor.models import (
    GithubApiConfig,
    GithubMonitoredTool,
    GithubPocEntry,
    KevCatalogEntry,
    PushConfig,
    PushLog,
    SyncJobLog,
    TranslationApiConfig,
    Vulnerability,
    VulnerabilityEvent,
    WatchRule,
)
from seceventmonitor.services.collectors import list_supported_vulnerability_sources
from seceventmonitor.services import settings as settings_service
from seceventmonitor.services.sync_service import ALL_SYNC_SOURCE_LABELS
from seceventmonitor.utils.affected_versions import deserialize_affected_entries, matches_affected_filters
from seceventmonitor.utils.timezone import format_datetime

KEV_SOURCE_LABEL = "CISA KEV"
OVERVIEW_SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")
SYNC_STATUS_LABELS = {
    "idle": "未运行",
    "queued": "排队中",
    "running": "运行中",
    "success": "成功",
    "failed": "失败",
    "partial": "部分成功",
}
SYNC_STATUS_BADGE_CLASSES = {
    "idle": "badge-status-idle",
    "queued": "badge-status-queued",
    "running": "badge-status-running",
    "success": "badge-status-success",
    "failed": "badge-status-failed",
    "partial": "badge-status-partial",
}
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
    now = datetime.now(UTC).replace(tzinfo=None)
    recent_cutoff = now - timedelta(hours=24)
    recent_week_cutoff = now - timedelta(days=7)

    severity_counts = _build_overview_severity_counts()
    event_metrics = _build_overview_event_metrics(recent_cutoff=recent_cutoff)
    config_metrics = _build_overview_config_metrics()
    sync_metrics = _build_overview_sync_metrics(recent_cutoff=recent_cutoff)
    github_metrics = _build_overview_github_metrics(recent_week_cutoff=recent_week_cutoff)
    push_metrics = _build_overview_push_metrics(recent_cutoff=recent_cutoff)
    source_summaries = _build_overview_source_summaries(timezone_name=timezone_name, recent_cutoff=recent_cutoff)
    sync_statuses = _build_overview_sync_statuses(timezone_name=timezone_name)

    vulnerability_count = sum(severity_counts.values())
    critical_count = severity_counts.get("critical", 0)
    high_count = severity_counts.get("high", 0)
    critical_high_count = critical_count + high_count
    new_event_count_24h = event_metrics["new_event_count_24h"]
    updated_event_count_24h = event_metrics["updated_event_count_24h"]
    push_config_count = config_metrics["push_config_count"]
    enabled_push_config_count = config_metrics["enabled_push_config_count"]
    translation_api_count = config_metrics["translation_api_count"]
    enabled_translation_api_count = config_metrics["enabled_translation_api_count"]
    github_api_config_count = config_metrics["github_api_config_count"]
    enabled_github_api_count = config_metrics["enabled_github_api_count"]
    watch_rule_count = config_metrics["watch_rule_count"]
    enabled_watch_rule_count = config_metrics["enabled_watch_rule_count"]
    active_sync_job_count = sync_metrics["active_sync_job_count"]
    failed_sync_job_count_24h = sync_metrics["failed_sync_job_count_24h"]
    github_tool_count = github_metrics["github_tool_count"]
    github_tools_synced_count = github_metrics["github_tools_synced_count"]
    github_tools_recently_updated_count = github_metrics["github_tools_recently_updated_count"]
    github_poc_count = github_metrics["github_poc_count"]
    github_poc_cve_count = github_metrics["github_poc_cve_count"]
    github_poc_new_count = github_metrics["github_poc_new_count"]
    github_poc_updated_count = github_metrics["github_poc_updated_count"]
    push_success_count_24h = push_metrics["push_success_count_24h"]
    push_failed_count_24h = push_metrics["push_failed_count_24h"]

    return {
        "vulnerability_count": vulnerability_count,
        "vulnerability_critical_high_count": critical_high_count,
        "new_event_count_24h": new_event_count_24h,
        "updated_event_count_24h": updated_event_count_24h,
        "push_config_count": push_config_count,
        "enabled_push_config_count": enabled_push_config_count,
        "translation_api_count": translation_api_count,
        "enabled_translation_api_count": enabled_translation_api_count,
        "github_api_config_count": github_api_config_count,
        "enabled_github_api_count": enabled_github_api_count,
        "watch_rule_count": watch_rule_count,
        "enabled_watch_rule_count": enabled_watch_rule_count,
        "kev_catalog_count": config_metrics["kev_catalog_count"],
        "active_sync_job_count": active_sync_job_count,
        "failed_sync_job_count_24h": failed_sync_job_count_24h,
        "github_tool_count": github_tool_count,
        "github_tools_synced_count": github_tools_synced_count,
        "github_tools_recently_updated_count": github_tools_recently_updated_count,
        "github_poc_count": github_poc_count,
        "github_poc_cve_count": github_poc_cve_count,
        "github_poc_new_count": github_poc_new_count,
        "github_poc_updated_count": github_poc_updated_count,
        "push_success_count_24h": push_success_count_24h,
        "push_failed_count_24h": push_failed_count_24h,
        "summary_metrics": [
            {
                "label": "漏洞总数",
                "value": vulnerability_count,
                "meta": f"已接入来源 {len(source_summaries)} 个",
            },
            {
                "label": "高危/严重",
                "value": critical_high_count,
                "meta": f"严重 {critical_count} / 高危 {high_count}",
            },
            {
                "label": "近 24 小时新增",
                "value": new_event_count_24h,
                "meta": "新增漏洞事件",
            },
            {
                "label": "近 24 小时更新",
                "value": updated_event_count_24h,
                "meta": "漏洞更新事件",
            },
            {
                "label": "GitHub 红队工具",
                "value": github_tool_count,
                "meta": f"已同步 {github_tools_synced_count} 个仓库",
            },
            {
                "label": "GitHub POC",
                "value": github_poc_count,
                "meta": f"覆盖 CVE {github_poc_cve_count} 个",
            },
            {
                "label": "近 24 小时推送成功",
                "value": push_success_count_24h,
                "meta": f"失败 {push_failed_count_24h} 次",
            },
            {
                "label": "运行中同步任务",
                "value": active_sync_job_count,
                "meta": f"24 小时失败 {failed_sync_job_count_24h} 次",
            },
        ],
        "severity_breakdown": [
            {"value": severity, "count": severity_counts.get(severity, 0)}
            for severity in OVERVIEW_SEVERITY_ORDER
        ],
        "coverage_metrics": [
            {
                "label": "监控规则",
                "value": _format_enabled_total(enabled_watch_rule_count, watch_rule_count),
                "description": "漏洞与关键字关注范围",
            },
            {
                "label": "推送配置",
                "value": _format_enabled_total(enabled_push_config_count, push_config_count),
                "description": "命中规则后的通知链路",
            },
            {
                "label": "GitHub API",
                "value": _format_enabled_total(enabled_github_api_count, github_api_config_count),
                "description": "GitHub 监控采集凭据",
            },
            {
                "label": "翻译 API",
                "value": _format_enabled_total(enabled_translation_api_count, translation_api_count),
                "description": "漏洞描述与修复建议翻译",
            },
        ],
        "github_metrics": [
            {
                "label": "监控仓库",
                "value": github_tool_count,
                "description": f"其中已同步 {github_tools_synced_count} 个仓库",
            },
            {
                "label": "近 7 天仓库更新",
                "value": github_tools_recently_updated_count,
                "description": "基于仓库最近更新时间统计",
            },
            {
                "label": "POC 覆盖 CVE",
                "value": github_poc_cve_count,
                "description": f"共跟踪 {github_poc_count} 条 POC 记录",
            },
            {
                "label": "待关注 POC",
                "value": f"{github_poc_new_count} / {github_poc_updated_count}",
                "description": "new / updated",
            },
        ],
        "source_summaries": source_summaries,
        "sync_statuses": sync_statuses,
    }


def _build_overview_severity_counts() -> dict[str, int]:
    rows = (
        db.session.query(
            func.lower(func.coalesce(Vulnerability.severity, "unknown")),
            func.count(Vulnerability.id),
        )
        .group_by(func.lower(func.coalesce(Vulnerability.severity, "unknown")))
        .all()
    )
    counts = {str(severity or "unknown"): int(count or 0) for severity, count in rows}
    for severity in OVERVIEW_SEVERITY_ORDER:
        counts.setdefault(severity, 0)
    return counts


def _build_overview_event_metrics(*, recent_cutoff: datetime) -> dict[str, int]:
    row = (
        db.session.execute(
            select(
                func.coalesce(
                    func.sum(case((VulnerabilityEvent.event_type == "new", 1), else_=0)),
                    0,
                ).label("new_event_count_24h"),
                func.coalesce(
                    func.sum(case((VulnerabilityEvent.event_type == "updated", 1), else_=0)),
                    0,
                ).label("updated_event_count_24h"),
            )
            .select_from(VulnerabilityEvent)
            .where(VulnerabilityEvent.created_at >= recent_cutoff)
        )
        .mappings()
        .one()
    )
    return _normalize_overview_metric_row(row)


def _build_overview_config_metrics() -> dict[str, int]:
    row = (
        db.session.execute(
            select(
                select(func.count())
                .select_from(PushConfig)
                .scalar_subquery()
                .label("push_config_count"),
                select(
                    func.coalesce(func.sum(case((PushConfig.enabled.is_(True), 1), else_=0)), 0)
                )
                .select_from(PushConfig)
                .scalar_subquery()
                .label("enabled_push_config_count"),
                select(func.count())
                .select_from(TranslationApiConfig)
                .scalar_subquery()
                .label("translation_api_count"),
                select(
                    func.coalesce(
                        func.sum(case((TranslationApiConfig.enabled.is_(True), 1), else_=0)),
                        0,
                    )
                )
                .select_from(TranslationApiConfig)
                .scalar_subquery()
                .label("enabled_translation_api_count"),
                select(func.count())
                .select_from(GithubApiConfig)
                .scalar_subquery()
                .label("github_api_config_count"),
                select(
                    func.coalesce(func.sum(case((GithubApiConfig.enabled.is_(True), 1), else_=0)), 0)
                )
                .select_from(GithubApiConfig)
                .scalar_subquery()
                .label("enabled_github_api_count"),
                select(func.count())
                .select_from(WatchRule)
                .scalar_subquery()
                .label("watch_rule_count"),
                select(
                    func.coalesce(func.sum(case((WatchRule.enabled.is_(True), 1), else_=0)), 0)
                )
                .select_from(WatchRule)
                .scalar_subquery()
                .label("enabled_watch_rule_count"),
                select(func.count())
                .select_from(KevCatalogEntry)
                .scalar_subquery()
                .label("kev_catalog_count"),
            )
        )
        .mappings()
        .one()
    )
    return _normalize_overview_metric_row(row)


def _build_overview_sync_metrics(*, recent_cutoff: datetime) -> dict[str, int]:
    active_statuses = ("queued", "running")
    row = (
        db.session.execute(
            select(
                func.coalesce(
                    func.sum(case((SyncJobLog.status.in_(active_statuses), 1), else_=0)),
                    0,
                ).label("active_sync_job_count"),
                func.coalesce(
                    func.sum(
                        case(
                            (
                                and_(
                                    SyncJobLog.status == "failed",
                                    SyncJobLog.created_at >= recent_cutoff,
                                ),
                                1,
                            ),
                            else_=0,
                        )
                    ),
                    0,
                ).label("failed_sync_job_count_24h"),
            )
            .select_from(SyncJobLog)
            .where(
                or_(
                    SyncJobLog.status.in_(active_statuses),
                    and_(
                        SyncJobLog.status == "failed",
                        SyncJobLog.created_at >= recent_cutoff,
                    ),
                )
            )
        )
        .mappings()
        .one()
    )
    return _normalize_overview_metric_row(row)


def _build_overview_github_metrics(*, recent_week_cutoff: datetime) -> dict[str, int]:
    row = (
        db.session.execute(
            select(
                select(func.count())
                .select_from(GithubMonitoredTool)
                .scalar_subquery()
                .label("github_tool_count"),
                select(func.count())
                .select_from(GithubMonitoredTool)
                .where(GithubMonitoredTool.last_synced_at.isnot(None))
                .scalar_subquery()
                .label("github_tools_synced_count"),
                select(func.count())
                .select_from(GithubMonitoredTool)
                .where(
                    GithubMonitoredTool.repo_updated_at.isnot(None),
                    GithubMonitoredTool.repo_updated_at >= recent_week_cutoff,
                )
                .scalar_subquery()
                .label("github_tools_recently_updated_count"),
                select(func.count())
                .select_from(GithubPocEntry)
                .scalar_subquery()
                .label("github_poc_count"),
                select(func.count(func.distinct(GithubPocEntry.cve_id)))
                .select_from(GithubPocEntry)
                .where(func.trim(func.coalesce(GithubPocEntry.cve_id, "")) != "")
                .scalar_subquery()
                .label("github_poc_cve_count"),
                select(func.count())
                .select_from(GithubPocEntry)
                .where(func.lower(func.coalesce(GithubPocEntry.status, "")) == "new")
                .scalar_subquery()
                .label("github_poc_new_count"),
                select(func.count())
                .select_from(GithubPocEntry)
                .where(func.lower(func.coalesce(GithubPocEntry.status, "")) == "updated")
                .scalar_subquery()
                .label("github_poc_updated_count"),
            )
        )
        .mappings()
        .one()
    )
    return _normalize_overview_metric_row(row)


def _build_overview_push_metrics(*, recent_cutoff: datetime) -> dict[str, int]:
    row = (
        db.session.execute(
            select(
                func.coalesce(
                    func.sum(case((PushLog.status == "success", 1), else_=0)),
                    0,
                ).label("push_success_count_24h"),
                func.coalesce(
                    func.sum(case((PushLog.status == "failed", 1), else_=0)),
                    0,
                ).label("push_failed_count_24h"),
            )
            .select_from(PushLog)
            .where(PushLog.created_at >= recent_cutoff)
        )
        .mappings()
        .one()
    )
    return _normalize_overview_metric_row(row)


def _build_overview_source_summaries(*, timezone_name: str, recent_cutoff: datetime) -> list[dict[str, str | int]]:
    severity_expr = func.lower(func.coalesce(Vulnerability.severity, "unknown"))
    critical_high_expr = case((severity_expr.in_(("critical", "high")), 1), else_=0)
    recent_new_expr = case((Vulnerability.created_at >= recent_cutoff, 1), else_=0)
    latest_seen_expr = func.max(func.coalesce(Vulnerability.last_seen_at, Vulnerability.created_at))

    source_rows = (
        db.session.query(
            Vulnerability.source,
            func.count(Vulnerability.id),
            func.sum(critical_high_expr),
            func.sum(recent_new_expr),
            latest_seen_expr,
        )
        .filter(Vulnerability.source.isnot(None))
        .group_by(Vulnerability.source)
        .order_by(func.count(Vulnerability.id).desc(), Vulnerability.source.asc())
        .all()
    )

    items = []
    for source, count, critical_high_count, new_count_24h, latest_seen_at in source_rows:
        normalized_source = str(source or "").strip()
        lowered_source = normalized_source.lower()
        if not normalized_source or lowered_source == "manual" or lowered_source.startswith("github"):
            continue
        if lowered_source in {"阿里云漏洞库", "aliyun_avd"}:
            continue
        items.append(
            {
                "source": normalized_source,
                "count": int(count or 0),
                "critical_high_count": int(critical_high_count or 0),
                "new_count_24h": int(new_count_24h or 0),
                "latest_seen_at": format_datetime(latest_seen_at, timezone_name) or "-",
            }
        )
    return items


def _build_overview_sync_statuses(*, timezone_name: str) -> list[dict[str, str]]:
    latest_job_subquery = (
        select(
            SyncJobLog.job_name.label("job_name"),
            SyncJobLog.status.label("status"),
            SyncJobLog.message.label("message"),
            SyncJobLog.finished_at.label("finished_at"),
            SyncJobLog.updated_at.label("updated_at"),
            SyncJobLog.created_at.label("created_at"),
            func.row_number()
            .over(
                partition_by=SyncJobLog.job_name,
                order_by=(SyncJobLog.created_at.desc(), SyncJobLog.id.desc()),
            )
            .label("row_number"),
        )
        .where(SyncJobLog.job_name.like("sync:%"))
        .subquery()
    )
    latest_success_subquery = (
        select(
            SyncJobLog.job_name.label("job_name"),
            SyncJobLog.finished_at.label("success_finished_at"),
            SyncJobLog.updated_at.label("success_updated_at"),
            SyncJobLog.created_at.label("success_created_at"),
            func.row_number()
            .over(
                partition_by=SyncJobLog.job_name,
                order_by=(SyncJobLog.created_at.desc(), SyncJobLog.id.desc()),
            )
            .label("row_number"),
        )
        .where(
            SyncJobLog.job_name.like("sync:%"),
            SyncJobLog.status == "success",
        )
        .subquery()
    )
    latest_rows = (
        db.session.execute(
            select(
                latest_job_subquery.c.job_name,
                latest_job_subquery.c.status,
                latest_job_subquery.c.message,
                latest_job_subquery.c.finished_at,
                latest_job_subquery.c.updated_at,
                latest_job_subquery.c.created_at,
                latest_success_subquery.c.success_finished_at,
                latest_success_subquery.c.success_updated_at,
                latest_success_subquery.c.success_created_at,
            )
            .select_from(latest_job_subquery)
            .outerjoin(
                latest_success_subquery,
                and_(
                    latest_success_subquery.c.job_name == latest_job_subquery.c.job_name,
                    latest_success_subquery.c.row_number == 1,
                ),
            )
            .where(latest_job_subquery.c.row_number == 1)
        )
        .mappings()
        .all()
    )
    latest_by_job_name = {str(row["job_name"]): row for row in latest_rows if row["job_name"]}

    items = []
    for source_key, source_label in ALL_SYNC_SOURCE_LABELS.items():
        job_name = f"sync:{source_key}"
        latest_row = latest_by_job_name.get(job_name)
        status = str((latest_row["status"] if latest_row is not None else "idle") or "idle")
        latest_job_time = (
            latest_row["finished_at"] or latest_row["updated_at"] or latest_row["created_at"]
            if latest_row is not None
            else None
        )
        latest_success_time = (
            latest_row["success_finished_at"] or latest_row["success_updated_at"] or latest_row["success_created_at"]
            if latest_row is not None
            else None
        )
        items.append(
            {
                "source": source_label,
                "status": status,
                "status_label": SYNC_STATUS_LABELS.get(status, status),
                "status_class": SYNC_STATUS_BADGE_CLASSES.get(status, "badge-status-idle"),
                "message": ((latest_row["message"] if latest_row is not None else "") or "").strip() or "暂无同步记录",
                "updated_at": format_datetime(latest_job_time, timezone_name) or "-",
                "last_success_at": format_datetime(latest_success_time, timezone_name) or "-",
            }
        )
    return items


def _format_enabled_total(enabled_count: int, total_count: int) -> str:
    return f"{enabled_count} / {total_count}"


def _normalize_overview_metric_row(row) -> dict[str, int]:
    return {str(key): int(value or 0) for key, value in dict(row).items()}


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
