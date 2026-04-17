import logging
import math
import threading
from collections.abc import Iterable
from datetime import UTC, datetime

from seceventmonitor.extensions import db
from seceventmonitor.models import KevCatalogEntry, SyncJobLog, Vulnerability, VulnerabilityEvent
from seceventmonitor.services.collectors import COLLECTOR_MAP, SYNC_SOURCE_LABELS, list_sync_source_options
from seceventmonitor.services.github_poc_service import sync_github_poc_entries
from seceventmonitor.services.github_monitor_service import refresh_github_monitored_tools
from seceventmonitor.services.pushers.service import (
    dispatch_github_poc_notifications,
    dispatch_github_tool_notifications,
    dispatch_vulnerability_notifications,
)
from seceventmonitor.services import settings as settings_service
from seceventmonitor.services.translation_service import infer_translation_language, translate_text_to_zh


ACTIVE_JOB_STATUSES = ("queued", "running")
_ACTIVE_SOURCES: set[str] = set()
_ACTIVE_SOURCES_LOCK = threading.Lock()
logger = logging.getLogger(__name__)
GITHUB_TOOLS_SYNC_SOURCE = "github_tools"
GITHUB_POC_SYNC_SOURCE = "github_pocs"
EXTRA_SYNC_SOURCE_LABELS = {
    GITHUB_TOOLS_SYNC_SOURCE: "红队工具",
    GITHUB_POC_SYNC_SOURCE: "POC监控",
}
ALL_SYNC_SOURCE_LABELS = {
    **SYNC_SOURCE_LABELS,
    **EXTRA_SYNC_SOURCE_LABELS,
}


def get_sync_source_options():
    options = list_sync_source_options()
    options.extend(
        {"value": key, "label": label}
        for key, label in EXTRA_SYNC_SOURCE_LABELS.items()
    )
    return options


def run_sync(source="all"):
    requested_sources = _normalize_sources(source)
    results = {}

    for source_name in requested_sources:
        job_id = _create_job(source_name, status="running", message="同步开始")
        results[source_name] = _run_source(source_name, job_id)

    return {
        "status": _merge_status(results),
        "sources": results,
    }


def start_sync_async(source="all"):
    requested_sources = _normalize_sources(source)
    busy_sources = _get_busy_sources(requested_sources)
    requested_labels = [ALL_SYNC_SOURCE_LABELS.get(item, item) for item in requested_sources]
    busy_labels = [ALL_SYNC_SOURCE_LABELS.get(item, item) for item in busy_sources]
    if busy_sources:
        return {
            "status": "busy",
            "message": f"同步任务已在后台执行：{', '.join(busy_labels)}",
            "sources": requested_sources,
            "active_sources": sorted(_list_active_sources()),
            "jobs": list_active_sync_jobs(limit=10),
        }

    job_ids: dict[str, int] = {}
    try:
        for source_name in requested_sources:
            job_ids[source_name] = _create_job(source_name, status="queued", message="等待后台任务启动")
        _mark_sources_active(requested_sources)
    finally:
        db.remove()

    worker = threading.Thread(
        target=_run_sync_async_worker,
        args=(requested_sources, job_ids),
        name=f"sync-{'-'.join(requested_sources)}",
        daemon=True,
    )
    worker.start()

    return {
        "status": "started",
        "message": f"后台同步已启动：{', '.join(requested_labels)}",
        "sources": requested_sources,
        "job_ids": job_ids,
    }


def list_active_sync_jobs(limit=10):
    timezone_name = settings_service.get_timezone_name()
    query = (
        SyncJobLog.query.filter(SyncJobLog.status.in_(ACTIVE_JOB_STATUSES))
        .order_by(SyncJobLog.created_at.desc())
        .limit(limit)
    )
    return [item.to_dict(timezone_name=timezone_name) for item in query.all()]


def get_vulnerability_sync_sources():
    return list(COLLECTOR_MAP.keys())


def clear_sync_jobs(*, active_only=True, sources=None):
    job_names = _normalize_sync_job_name_filters(sources)
    query = SyncJobLog.query.filter(SyncJobLog.job_name.like("sync:%"))
    if active_only:
        query = query.filter(SyncJobLog.status.in_(ACTIVE_JOB_STATUSES))
    if job_names:
        query = query.filter(SyncJobLog.job_name.in_(job_names))

    rows = query.with_entities(SyncJobLog.id, SyncJobLog.job_name, SyncJobLog.status).all()
    if not rows:
        return {
            "deleted": 0,
            "active_only": active_only,
            "job_names": [],
            "statuses": [],
        }

    deleted_ids = [row.id for row in rows]
    deleted_job_names = sorted({row.job_name for row in rows})
    deleted_statuses = sorted({row.status for row in rows})
    SyncJobLog.query.filter(SyncJobLog.id.in_(deleted_ids)).delete(synchronize_session=False)
    db.session.commit()
    return {
        "deleted": len(deleted_ids),
        "active_only": active_only,
        "job_names": deleted_job_names,
        "statuses": deleted_statuses,
    }


def _run_single_source(source_name, collector_cls, job_id):
    job_name = f"sync:{source_name}"
    started_at = datetime.now(UTC)
    source_label = SYNC_SOURCE_LABELS.get(source_name, source_name.upper())
    job = db.session.get(SyncJobLog, job_id)
    if job is None:
        job_id = _create_job(source_name, status="running", message="同步开始")
        job = db.session.get(SyncJobLog, job_id)
    else:
        job.status = "running"
        job.message = "同步开始"
        job.started_at = job.started_at or started_at
        job.finished_at = None
        db.session.commit()

    try:
        collector = collector_cls()
        records = collector.fetch(
            since=get_last_success_time(job_name),
            progress_callback=_build_progress_callback(job.id, source_name),
        )
        _update_job_state(
            job.id,
            status="running",
            message=f"{source_label} 拉取完成，共 {len(records)} 条，开始入库",
        )
        if source_name == "kev":
            inserted, updated, notification_targets = upsert_kev_entries(records)
        else:
            inserted, updated, notification_targets = upsert_vulnerabilities(records)
        queued_notifications = len(notification_targets)
        job = db.session.get(SyncJobLog, job.id)
        job.status = "success"
        job.message = f"抓取 {len(records)} 条，新增 {inserted} 条，更新 {updated} 条，待异步筛选推送 {queued_notifications} 条"
        job.finished_at = datetime.now(UTC)
        db.session.commit()
        _start_post_commit_notifications(job.id, notification_targets)
        return {
            "status": job.status,
            "message": job.message,
            "record_count": len(records),
            "inserted": inserted,
            "updated": updated,
            "queued_notifications": queued_notifications,
        }
    except Exception as exc:
        db.session.rollback()
        failed_job = db.session.get(SyncJobLog, job_id)
        if failed_job is None:
            failed_job = SyncJobLog(
                job_name=job_name,
                status="failed",
                message=str(exc),
                started_at=started_at,
            )
            db.session.add(failed_job)
        failed_job.status = "failed"
        failed_job.message = str(exc)
        failed_job.finished_at = datetime.now(UTC)
        db.session.commit()
        return {
            "status": "failed",
            "message": str(exc),
            "record_count": 0,
            "inserted": 0,
            "updated": 0,
            "queued_notifications": 0,
        }


def _run_cnnvd_source(job_id):
    source_name = "cnnvd"
    job_name = f"sync:{source_name}"
    started_at = datetime.now(UTC)
    source_label = SYNC_SOURCE_LABELS.get(source_name, source_name.upper())
    job = db.session.get(SyncJobLog, job_id)
    if job is None:
        job_id = _create_job(source_name, status="running", message="同步开始")
        job = db.session.get(SyncJobLog, job_id)
    else:
        job.status = "running"
        job.message = "同步开始"
        job.started_at = job.started_at or started_at
        job.finished_at = None
        db.session.commit()

    try:
        collector = COLLECTOR_MAP[source_name]()
        last_success_time = get_last_success_time(job_name)
        use_code_boundary = last_success_time is not None
        inserted = 0
        updated = 0
        record_count = 0
        notification_targets = []

        for batch in collector.iter_batches(
            since=None if use_code_boundary else last_success_time,
            full_history=use_code_boundary,
            progress_callback=_build_progress_callback(job.id, source_name),
            stop_on_existing=use_code_boundary,
        ):
            batch_inserted, batch_updated, batch_targets = upsert_vulnerabilities(batch)
            inserted += batch_inserted
            updated += batch_updated
            record_count += len(batch)
            notification_targets.extend(batch_targets)

            job = db.session.get(SyncJobLog, job.id)
            if job is not None:
                job.status = "running"
                job.message = f"{source_label} 已入库 {record_count} 条，新增 {inserted} 条，更新 {updated} 条"
            db.session.commit()

        queued_notifications = len(notification_targets)
        job = db.session.get(SyncJobLog, job.id)
        job.status = "success"
        job.message = f"抓取 {record_count} 条，新增 {inserted} 条，更新 {updated} 条，待异步筛选推送 {queued_notifications} 条"
        job.finished_at = datetime.now(UTC)
        db.session.commit()
        _start_post_commit_notifications(job.id, notification_targets)
        return {
            "status": job.status,
            "message": job.message,
            "record_count": record_count,
            "inserted": inserted,
            "updated": updated,
            "queued_notifications": queued_notifications,
        }
    except Exception as exc:
        db.session.rollback()
        failed_job = db.session.get(SyncJobLog, job_id)
        if failed_job is None:
            failed_job = SyncJobLog(
                job_name=job_name,
                status="failed",
                message=str(exc),
                started_at=started_at,
            )
            db.session.add(failed_job)
        failed_job.status = "failed"
        failed_job.message = str(exc)
        failed_job.finished_at = datetime.now(UTC)
        db.session.commit()
        return {
            "status": "failed",
            "message": str(exc),
            "record_count": 0,
            "inserted": 0,
            "updated": 0,
            "queued_notifications": 0,
        }


def _run_github_tools_source(job_id):
    source_label = ALL_SYNC_SOURCE_LABELS.get(GITHUB_TOOLS_SYNC_SOURCE, GITHUB_TOOLS_SYNC_SOURCE)
    started_at = datetime.now(UTC)
    job_name = f"sync:{GITHUB_TOOLS_SYNC_SOURCE}"
    job = db.session.get(SyncJobLog, job_id)
    if job is None:
        job_id = _create_job(GITHUB_TOOLS_SYNC_SOURCE, status="running", message="同步开始")
        job = db.session.get(SyncJobLog, job_id)
    else:
        job.status = "running"
        job.message = "同步开始"
        job.started_at = job.started_at or started_at
        job.finished_at = None
        db.session.commit()

    try:
        result = refresh_github_monitored_tools(progress_callback=_build_progress_callback(job.id, GITHUB_TOOLS_SYNC_SOURCE))
        queued_notifications = int(result.get("queued_notifications") or 0)
        error_suffix = ""
        if result["failed"]:
            preview = "；".join(result["errors"][:2])
            if preview:
                error_suffix = f"；失败 {result['failed']} 个：{preview}"
            else:
                error_suffix = f"；失败 {result['failed']} 个"
        job = db.session.get(SyncJobLog, job.id)
        job.status = "success"
        job.message = f"刷新 {result['total']} 个仓库，更新 {result['updated']} 个，待异步筛选推送 {queued_notifications} 条{error_suffix}"
        job.finished_at = datetime.now(UTC)
        db.session.commit()
        _start_post_commit_github_tool_notifications(job.id, result.get("notification_targets") or [])
        return {
            "status": job.status,
            "message": job.message,
            "record_count": result["total"],
            "inserted": 0,
            "updated": result["updated"],
            "queued_notifications": queued_notifications,
        }
    except Exception as exc:
        db.session.rollback()
        failed_job = db.session.get(SyncJobLog, job_id)
        if failed_job is None:
            failed_job = SyncJobLog(
                job_name=job_name,
                status="failed",
                message=str(exc),
                started_at=started_at,
            )
            db.session.add(failed_job)
        failed_job.status = "failed"
        failed_job.message = str(exc)
        failed_job.finished_at = datetime.now(UTC)
        db.session.commit()
        return {
            "status": "failed",
            "message": str(exc),
            "record_count": 0,
            "inserted": 0,
            "updated": 0,
            "queued_notifications": 0,
        }


def _run_github_poc_source(job_id):
    source_label = ALL_SYNC_SOURCE_LABELS.get(GITHUB_POC_SYNC_SOURCE, GITHUB_POC_SYNC_SOURCE)
    started_at = datetime.now(UTC)
    job_name = f"sync:{GITHUB_POC_SYNC_SOURCE}"
    job = db.session.get(SyncJobLog, job_id)
    if job is None:
        job_id = _create_job(GITHUB_POC_SYNC_SOURCE, status="running", message="同步开始")
        job = db.session.get(SyncJobLog, job_id)
    else:
        job.status = "running"
        job.message = "同步开始"
        job.started_at = job.started_at or started_at
        job.finished_at = None
        db.session.commit()

    try:
        result = sync_github_poc_entries(progress_callback=_build_progress_callback(job.id, GITHUB_POC_SYNC_SOURCE))
        queued_notifications = int(result.get("queued_notifications") or 0)
        total_files = int(result.get("total_files") or 0)
        changed_files = int(result.get("changed_files") or 0)
        inserted = int(result.get("inserted") or 0)
        updated = int(result.get("updated") or 0)
        deleted = int(result.get("deleted") or 0)
        job = db.session.get(SyncJobLog, job.id)
        job.status = "success"
        job.message = (
            f"扫描 {total_files} 个索引文件，变更 {changed_files} 个，新增 {inserted} 条，"
            f"更新 {updated} 条，删除 {deleted} 条，待异步筛选推送 {queued_notifications} 条"
        )
        job.finished_at = datetime.now(UTC)
        db.session.commit()
        _start_post_commit_github_poc_notifications(job.id, result.get("notification_targets") or [])
        return {
            "status": job.status,
            "message": job.message,
            "record_count": total_files,
            "inserted": inserted,
            "updated": updated,
            "queued_notifications": queued_notifications,
        }
    except Exception as exc:
        db.session.rollback()
        failed_job = db.session.get(SyncJobLog, job_id)
        if failed_job is None:
            failed_job = SyncJobLog(
                job_name=job_name,
                status="failed",
                message=str(exc),
                started_at=started_at,
            )
            db.session.add(failed_job)
        failed_job.status = "failed"
        failed_job.message = str(exc)
        failed_job.finished_at = datetime.now(UTC)
        db.session.commit()
        return {
            "status": "failed",
            "message": str(exc),
            "record_count": 0,
            "inserted": 0,
            "updated": 0,
            "queued_notifications": 0,
        }


def get_last_success_time(job_name):
    item = (
        SyncJobLog.query.filter_by(job_name=job_name, status="success")
        .order_by(SyncJobLog.finished_at.desc())
        .first()
    )
    if item and item.finished_at:
        return item.finished_at
    return None


def upsert_vulnerabilities(records):
    inserted = 0
    updated = 0
    notification_targets = []

    for item in records:
        vulnerability = Vulnerability.query.filter_by(vuln_key=item["vuln_key"]).first()
        if vulnerability is None:
            vulnerability = Vulnerability(vuln_key=item["vuln_key"])
            db.session.add(vulnerability)
            change_type = "new"
            inserted += 1
        else:
            change_type = "updated" if _has_changed(vulnerability, item) else None
            if change_type == "updated":
                updated += 1

        refresh_description_translation = _should_refresh_description_translation(vulnerability, item)
        refresh_remediation_translation = _should_refresh_remediation_translation(vulnerability, item)
        _apply_vulnerability_data(vulnerability, item)
        if refresh_description_translation:
            _apply_vulnerability_description_translation(vulnerability, item)
        if refresh_remediation_translation:
            _apply_vulnerability_remediation_translation(vulnerability, item)

        if change_type:
            vulnerability.status = change_type
            db.session.flush()
            db.session.add(
                VulnerabilityEvent(
                    vulnerability_id=vulnerability.id,
                    event_type=change_type,
                    message=f"{item['source']} {change_type}",
                    payload=item.get("payload"),
                )
            )
            notification_targets.append(_build_notification_target(vulnerability))

    return inserted, updated, notification_targets


def upsert_kev_entries(records):
    inserted = 0
    updated = 0
    notification_targets = []

    cve_ids = []
    for item in records:
        cve_id = str(item.get("cve_id") or "").strip().upper()
        if not cve_id:
            continue
        cve_ids.append(cve_id)

    if not cve_ids:
        return inserted, updated, notification_targets

    existing_entries = {
        item.cve_id.upper(): item
        for item in KevCatalogEntry.query.filter(KevCatalogEntry.cve_id.in_(cve_ids)).all()
    }
    new_cve_ids = []
    for cve_id in cve_ids:
        if cve_id in existing_entries:
            continue
        entry = KevCatalogEntry(cve_id=cve_id)
        db.session.add(entry)
        existing_entries[cve_id] = entry
        new_cve_ids.append(cve_id)
        inserted += 1

    if new_cve_ids:
        db.session.flush()
        notification_targets = _build_kev_notification_targets(new_cve_ids)
    return inserted, updated, notification_targets


def _apply_vulnerability_data(vulnerability, item):
    vulnerability.cve_id = item.get("cve_id") or ""
    vulnerability.title = item.get("title") or ""
    vulnerability.description = item.get("description") or ""
    vulnerability.description_lang = item.get("description_lang")
    vulnerability.severity = item.get("severity") or "unknown"
    vulnerability.vuln_status = item.get("vuln_status")
    vulnerability.cvss_version = item.get("cvss_version")
    vulnerability.base_score = item.get("base_score")
    vulnerability.base_severity = item.get("base_severity")
    vulnerability.vector_string = item.get("vector_string")
    vulnerability.attack_vector = item.get("attack_vector")
    vulnerability.attack_complexity = item.get("attack_complexity")
    vulnerability.attack_requirements = item.get("attack_requirements")
    vulnerability.privileges_required = item.get("privileges_required")
    vulnerability.user_interaction = item.get("user_interaction")
    vulnerability.scope = item.get("scope")
    vulnerability.exploit_maturity = item.get("exploit_maturity")
    vulnerability.patch_status = item.get("patch_status")
    vulnerability.confidentiality_impact = item.get("confidentiality_impact")
    vulnerability.integrity_impact = item.get("integrity_impact")
    vulnerability.availability_impact = item.get("availability_impact")
    vulnerability.exploitability_score = item.get("exploitability_score")
    vulnerability.impact_score = item.get("impact_score")
    vulnerability.affected_versions = item.get("affected_versions")
    vulnerability.affected_products = item.get("affected_products")
    vulnerability.affected_version_data = item.get("affected_version_data")
    vulnerability.remediation = item.get("remediation")
    vulnerability.source_payload = item.get("source_payload")
    vulnerability.source = item.get("source") or "manual"
    vulnerability.reference_url = item.get("reference_url") or ""
    vulnerability.published_at = item.get("published_at")
    vulnerability.last_seen_at = item.get("last_seen_at") or item.get("published_at")


def _has_changed(vulnerability, item):
    comparable_fields = [
        "cve_id",
        "title",
        "description",
        "description_lang",
        "severity",
        "vuln_status",
        "cvss_version",
        "base_score",
        "base_severity",
        "vector_string",
        "attack_vector",
        "attack_complexity",
        "attack_requirements",
        "privileges_required",
        "user_interaction",
        "scope",
        "exploit_maturity",
        "patch_status",
        "confidentiality_impact",
        "integrity_impact",
        "availability_impact",
        "exploitability_score",
        "impact_score",
        "affected_versions",
        "affected_products",
        "affected_version_data",
        "remediation",
        "source_payload",
        "source",
        "reference_url",
    ]
    for field_name in comparable_fields:
        if getattr(vulnerability, field_name) != item.get(field_name):
            return True
    if vulnerability.published_at != item.get("published_at"):
        return True

    existing_last_seen = vulnerability.last_seen_at
    incoming_last_seen = item.get("last_seen_at") or item.get("published_at")
    if existing_last_seen != incoming_last_seen:
        return True

    return False


def _build_notification_target(vulnerability):
    return {
        "id": vulnerability.id,
        "cve_id": vulnerability.cve_id,
        "title": vulnerability.title,
        "description": vulnerability.description,
        "translated_description": vulnerability.translated_description,
        "remediation": vulnerability.remediation,
        "translated_remediation": vulnerability.translated_remediation,
        "description_lang": vulnerability.description_lang,
        "severity": vulnerability.severity,
        "source": vulnerability.source,
        "status": vulnerability.status,
        "vuln_status": vulnerability.vuln_status,
        "reference_url": vulnerability.reference_url,
        "scope": vulnerability.scope,
        "exploit_maturity": vulnerability.exploit_maturity,
        "patch_status": vulnerability.patch_status,
        "affected_versions": vulnerability.affected_versions,
        "affected_products": vulnerability.affected_products,
        "affected_version_data": vulnerability.affected_version_data,
    }


def _build_kev_notification_targets(cve_ids: list[str]):
    if not cve_ids:
        return []

    vulnerabilities = (
        Vulnerability.query.filter(Vulnerability.cve_id.in_(cve_ids))
        .order_by(Vulnerability.source.asc(), Vulnerability.id.asc())
        .all()
    )
    targets = []
    seen_ids = set()
    for vulnerability in vulnerabilities:
        if vulnerability.id in seen_ids:
            continue
        seen_ids.add(vulnerability.id)
        targets.append(_build_notification_target(vulnerability))
    return targets


def _start_post_commit_notifications(job_id, notification_targets):
    if not notification_targets:
        return

    try:
        dispatch_vulnerability_notifications(notification_targets)
    except Exception as exc:
        logger.exception("failed to start async notification delivery for sync job %s", job_id)
        job = db.session.get(SyncJobLog, job_id)
        if job is None:
            return
        job.message = f"{job.message}；异步推送启动失败: {exc}"
        db.session.commit()


def _start_post_commit_github_tool_notifications(job_id, notification_targets):
    if not notification_targets:
        return

    try:
        dispatch_github_tool_notifications(notification_targets)
    except Exception as exc:
        logger.exception("failed to start async github tool notification delivery for sync job %s", job_id)
        job = db.session.get(SyncJobLog, job_id)
        if job is None:
            return
        job.message = f"{job.message}；异步推送启动失败: {exc}"
        db.session.commit()


def _start_post_commit_github_poc_notifications(job_id, notification_targets):
    if not notification_targets:
        return

    try:
        dispatch_github_poc_notifications(notification_targets)
    except Exception as exc:
        logger.exception("failed to start async github poc notification delivery for sync job %s", job_id)
        job = db.session.get(SyncJobLog, job_id)
        if job is None:
            return
        job.message = f"{job.message}；异步推送启动失败: {exc}"
        db.session.commit()


def _merge_status(results):
    statuses = {item["status"] for item in results.values()}
    if statuses == {"success"}:
        return "success"
    if "failed" in statuses:
        return "partial" if "success" in statuses else "failed"
    return "success"


def _normalize_sources(source):
    if source in (None, "", "all"):
        requested_sources = [*COLLECTOR_MAP.keys(), GITHUB_TOOLS_SYNC_SOURCE, GITHUB_POC_SYNC_SOURCE]
    elif isinstance(source, str):
        requested_sources = [source]
    elif isinstance(source, Iterable):
        requested_sources = [str(item).strip() for item in source if str(item).strip()]
        if not requested_sources:
            requested_sources = [*COLLECTOR_MAP.keys(), GITHUB_TOOLS_SYNC_SOURCE, GITHUB_POC_SYNC_SOURCE]
    else:
        requested_sources = [str(source).strip()]

    deduplicated_sources = []
    seen = set()
    for name in requested_sources:
        normalized_name = str(name).strip()
        if not normalized_name or normalized_name in seen:
            continue
        seen.add(normalized_name)
        deduplicated_sources.append(normalized_name)

    unsupported = [name for name in deduplicated_sources if name not in ALL_SYNC_SOURCE_LABELS]
    if unsupported:
        raise ValueError(f"不支持的同步源: {', '.join(unsupported)}")
    return deduplicated_sources


def _normalize_sync_job_name_filters(sources):
    if sources is None:
        return []
    if isinstance(sources, str):
        source_items = [sources]
    else:
        source_items = list(sources)

    normalized = []
    seen = set()
    for item in source_items:
        value = str(item).strip()
        if not value:
            continue
        job_name = value if value.startswith("sync:") else f"sync:{value}"
        if job_name in seen:
            continue
        seen.add(job_name)
        normalized.append(job_name)
    return normalized


def _create_job(source_name, status, message):
    now = datetime.now(UTC)
    job = SyncJobLog(
        job_name=f"sync:{source_name}",
        status=status,
        message=message,
        started_at=now,
        finished_at=None,
    )
    db.session.add(job)
    db.session.commit()
    return job.id


def _build_progress_callback(job_id, source_name):
    if source_name in {GITHUB_TOOLS_SYNC_SOURCE, GITHUB_POC_SYNC_SOURCE}:
        def callback(**progress):
            current_index = progress.get("current_index", 0)
            total_count = progress.get("total_count", 0)
            tool_name = progress.get("tool_name", "")
            source_label = ALL_SYNC_SOURCE_LABELS.get(source_name, source_name)
            message = f"{source_label} 刷新中，第 {current_index}/{total_count} 个"
            if tool_name:
                message = f"{message}，当前 {tool_name}"
            _update_job_state(job_id, status="running", message=message)

        return callback

    if source_name not in {"nvd", "oscs", "cnnvd"}:
        return None

    def callback(**progress):
        fetched_count = progress.get("fetched_count", 0)
        total_results = progress.get("total_results")
        page_index = progress.get("page_index", 0)
        page_size = progress.get("page_size") or 1
        source_label = ALL_SYNC_SOURCE_LABELS.get(source_name, source_name.upper())
        if total_results:
            total_pages = math.ceil(total_results / page_size)
            message = f"{source_label} 拉取中，第 {page_index}/{total_pages} 页，已抓取 {fetched_count}/{total_results} 条"
        else:
            message = f"{source_label} 拉取中，第 {page_index} 页，已抓取 {fetched_count} 条"
        _update_job_state(job_id, status="running", message=message)

    return callback


def _update_job_state(job_id, status=None, message=None):
    job = db.session.get(SyncJobLog, job_id)
    if job is None:
        return
    if status is not None:
        job.status = status
    if message is not None:
        job.message = message
        db.session.commit()


def _should_refresh_description_translation(vulnerability, item):
    incoming_description = (item.get("description") or "").strip()
    incoming_lang = item.get("description_lang")
    if not incoming_description:
        return True
    if vulnerability.id is None:
        return True
    if (vulnerability.description or "") != incoming_description:
        return True
    if vulnerability.description_lang != incoming_lang:
        return True
    return not (vulnerability.translated_description or "").strip()


def _apply_vulnerability_description_translation(vulnerability, item):
    description = (item.get("description") or "").strip()
    if not description:
        vulnerability.translated_description = ""
        vulnerability.translated_at = None
        return

    translated = translate_text_to_zh(description, item.get("description_lang"))
    vulnerability.translated_description = translated or ""
    vulnerability.translated_at = datetime.now(UTC).replace(tzinfo=None) if translated else None


def _should_refresh_remediation_translation(vulnerability, item):
    incoming_remediation = (item.get("remediation") or "").strip()
    if not incoming_remediation:
        return True
    if vulnerability.id is None:
        return True
    if (vulnerability.remediation or "") != incoming_remediation:
        return True
    return not (vulnerability.translated_remediation or "").strip()


def _apply_vulnerability_remediation_translation(vulnerability, item):
    remediation = (item.get("remediation") or "").strip()
    if not remediation:
        vulnerability.translated_remediation = ""
        vulnerability.translated_remediation_at = None
        return

    source_language = infer_translation_language(remediation, item.get("description_lang"))
    translated = translate_text_to_zh(remediation, source_language)
    vulnerability.translated_remediation = translated or ""
    vulnerability.translated_remediation_at = datetime.now(UTC).replace(tzinfo=None) if translated else None


def _run_sync_async_worker(requested_sources, job_ids):
    try:
        for source_name in requested_sources:
            _run_source(source_name, job_ids[source_name])
    finally:
        db.remove()
        _mark_sources_inactive(requested_sources)


def _run_source(source_name, job_id):
    if source_name == "cnnvd":
        return _run_cnnvd_source(job_id)
    if source_name == GITHUB_TOOLS_SYNC_SOURCE:
        return _run_github_tools_source(job_id)
    if source_name == GITHUB_POC_SYNC_SOURCE:
        return _run_github_poc_source(job_id)
    collector_cls = COLLECTOR_MAP.get(source_name)
    if collector_cls is None:
        _update_job_state(job_id, status="failed", message="不支持的同步源")
        return {"status": "error", "message": "不支持的同步源"}
    return _run_single_source(source_name, collector_cls, job_id)


def _get_busy_sources(requested_sources):
    with _ACTIVE_SOURCES_LOCK:
        return sorted(set(requested_sources) & _ACTIVE_SOURCES)


def _list_active_sources():
    with _ACTIVE_SOURCES_LOCK:
        return set(_ACTIVE_SOURCES)


def _mark_sources_active(sources):
    with _ACTIVE_SOURCES_LOCK:
        _ACTIVE_SOURCES.update(sources)


def _mark_sources_inactive(sources):
    with _ACTIVE_SOURCES_LOCK:
        _ACTIVE_SOURCES.difference_update(sources)
