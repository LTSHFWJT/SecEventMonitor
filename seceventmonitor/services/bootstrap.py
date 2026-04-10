from sqlalchemy import text

from seceventmonitor.extensions import db
from seceventmonitor.models import PushConfig, PushLog, PushRule, SyncJobLog, Vulnerability, VulnerabilityEvent
from seceventmonitor.services.push_config_service import migrate_legacy_push_configs
from seceventmonitor.services.settings import ensure_default_push_channels, ensure_default_settings
from seceventmonitor.utils.affected_versions import (
    build_affected_products_text,
    parse_affected_versions_text,
    serialize_affected_entries,
)


def initialize_database():
    db.create_all()
    if db.engine.url.drivername.startswith("sqlite"):
        with db.engine.begin() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL;"))
            conn.execute(text("PRAGMA synchronous=NORMAL;"))
            conn.execute(text("PRAGMA foreign_keys=ON;"))
            conn.execute(text("PRAGMA busy_timeout=5000;"))
            _ensure_sqlite_columns(
                conn,
                "vulnerabilities",
                {
                    "description_lang": "TEXT",
                    "translated_description": "TEXT",
                    "translated_at": "DATETIME",
                    "translated_remediation": "TEXT",
                    "translated_remediation_at": "DATETIME",
                    "vuln_status": "TEXT",
                    "cvss_version": "TEXT",
                    "base_score": "REAL",
                    "base_severity": "TEXT",
                    "vector_string": "TEXT",
                    "attack_vector": "TEXT",
                    "attack_complexity": "TEXT",
                    "attack_requirements": "TEXT",
                    "privileges_required": "TEXT",
                    "user_interaction": "TEXT",
                    "scope": "TEXT",
                    "exploit_maturity": "TEXT",
                    "patch_status": "TEXT",
                    "confidentiality_impact": "TEXT",
                    "integrity_impact": "TEXT",
                    "availability_impact": "TEXT",
                    "exploitability_score": "REAL",
                    "impact_score": "REAL",
                    "affected_versions": "TEXT",
                    "affected_products": "TEXT",
                    "affected_version_data": "TEXT",
                    "remediation": "TEXT",
                    "source_payload": "TEXT",
                },
            )
            _ensure_sqlite_columns(
                conn,
                "push_logs",
                {
                    "push_config_id": "INTEGER",
                    "github_tool_id": "INTEGER",
                },
            )
            conn.execute(text("UPDATE vulnerabilities SET source = 'NVD' WHERE lower(source) = 'nvd'"))
            _backfill_affected_version_search_fields(conn)


def seed_default_records():
    ensure_default_settings()
    ensure_default_push_channels()
    migrate_legacy_push_configs()
    _cleanup_removed_aliyun_support()
    db.session.commit()


def _ensure_sqlite_columns(conn, table_name, columns):
    existing_columns = {
        row[1]
        for row in conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    }
    for column_name, column_type in columns.items():
        if column_name in existing_columns:
            continue
        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


def _backfill_affected_version_search_fields(conn):
    rows = conn.execute(
        text(
            """
            SELECT id, affected_versions
            FROM vulnerabilities
            WHERE affected_versions IS NOT NULL
              AND trim(affected_versions) != ''
              AND (
                affected_products IS NULL OR trim(affected_products) = ''
                OR affected_version_data IS NULL OR trim(affected_version_data) = ''
              )
            """
        )
    ).fetchall()

    for row in rows:
        entries = parse_affected_versions_text(row[1])
        if not entries:
            continue
        conn.execute(
            text(
                """
                UPDATE vulnerabilities
                SET affected_products = :affected_products,
                    affected_version_data = :affected_version_data
                WHERE id = :vulnerability_id
                """
            ),
            {
                "vulnerability_id": row[0],
                "affected_products": build_affected_products_text(entries),
                "affected_version_data": serialize_affected_entries(entries),
            },
        )


def _cleanup_removed_aliyun_support():
    removed_source_values = {"阿里云漏洞库", "aliyun_avd"}
    removed_source_values_lower = {item.lower() for item in removed_source_values}

    vulnerabilities = (
        Vulnerability.query.filter(
            (Vulnerability.source == "阿里云漏洞库")
            | Vulnerability.vuln_key.like("aliyun-avd:%")
        )
        .all()
    )
    vulnerability_ids = [item.id for item in vulnerabilities]
    if vulnerability_ids:
        VulnerabilityEvent.query.filter(VulnerabilityEvent.vulnerability_id.in_(vulnerability_ids)).delete(
            synchronize_session=False
        )
        PushLog.query.filter(PushLog.vulnerability_id.in_(vulnerability_ids)).delete(synchronize_session=False)
        Vulnerability.query.filter(Vulnerability.id.in_(vulnerability_ids)).delete(synchronize_session=False)

    SyncJobLog.query.filter(SyncJobLog.job_name == "sync:aliyun_avd").delete(synchronize_session=False)
    PushRule.query.filter(PushRule.source.in_(removed_source_values)).delete(synchronize_session=False)

    deleted_config_ids: list[int] = []
    for config in PushConfig.query.all():
        original_items = list(config.rule_items or [])
        kept_items = []
        changed = False
        for item in original_items:
            source = str((item or {}).get("source") or "").strip().lower()
            if source in removed_source_values_lower:
                changed = True
                continue
            kept_items.append(item)

        if not changed:
            continue
        if kept_items:
            config.rule_items = kept_items
            continue
        deleted_config_ids.append(config.id)
        db.session.delete(config)

    if deleted_config_ids:
        PushLog.query.filter(PushLog.push_config_id.in_(deleted_config_ids)).delete(synchronize_session=False)
