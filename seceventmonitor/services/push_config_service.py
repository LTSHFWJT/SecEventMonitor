import math
from urllib.parse import urlparse

from seceventmonitor.extensions import db
from seceventmonitor.models import KevCatalogEntry, PushChannel, PushConfig, PushRule
from seceventmonitor.services import settings as settings_service
from seceventmonitor.services.push_rule_service import SEVERITY_RANK
from seceventmonitor.utils.affected_versions import deserialize_affected_entries, matches_affected_filters
from seceventmonitor.utils.enum_labels import enum_label

KEV_SOURCE_LABEL = "CISA KEV"
RULE_TYPE_VULNERABILITY = "vulnerability"
RULE_TYPE_GITHUB_TOOL = "github_tool"
GITHUB_TOOL_EVENT_LABELS = {
    "new_repo": "新增仓库",
    "repo_updated": "仓库信息更新",
    "version_updated": "新版本发布/版本变化",
}
GITHUB_TOOL_ALL_STATUS = "all"


CHANNEL_LABELS = {
    "dingding": "钉钉",
    "lark": "飞书",
}


def list_push_configs_paginated(page=1, page_size=10):
    timezone_name = settings_service.get_timezone_name()
    page = max(int(page or 1), 1)
    page_size = min(max(int(page_size or 10), 1), 100)

    query = PushConfig.query.order_by(PushConfig.created_at.desc(), PushConfig.id.desc())
    total = query.count()
    total_pages = max(1, math.ceil(total / page_size)) if total else 1
    page = min(page, total_pages)
    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()

    return {
        "items": [_serialize_push_config(item, timezone_name=timezone_name) for item in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }


def list_enabled_push_configs():
    return PushConfig.query.filter_by(enabled=True).order_by(PushConfig.id.asc()).all()


def create_push_config(
    *,
    name: str,
    channel_type: str,
    webhook_url: str,
    secret: str = "",
    enabled: bool = True,
    rule_items: list[dict] | None = None,
):
    name = (name or "").strip()
    channel_type = (channel_type or "").strip().lower()
    webhook_url = (webhook_url or "").strip()
    secret = (secret or "").strip()

    if not name:
        raise ValueError("推送规则名称不能为空")
    if channel_type not in CHANNEL_LABELS:
        raise ValueError("推送通道不支持")
    if not webhook_url:
        raise ValueError("Webhook URL 不能为空")

    normalized_rules = _normalize_rule_items(rule_items or [])
    if not normalized_rules:
        raise ValueError("至少需要配置一条推送规则")

    config = PushConfig(
        name=name,
        channel_type=channel_type,
        enabled=bool(enabled),
        webhook_url=webhook_url,
        secret=secret,
        rule_items=normalized_rules,
    )
    db.session.add(config)
    db.session.commit()
    return _serialize_push_config(config, timezone_name=settings_service.get_timezone_name())


def update_push_config(
    config_id: int,
    *,
    name: str,
    channel_type: str,
    webhook_url: str,
    secret: str = "",
    enabled: bool = True,
    rule_items: list[dict] | None = None,
):
    config = db.session.get(PushConfig, config_id)
    if config is None:
        raise ValueError("推送配置不存在")

    name = (name or "").strip()
    channel_type = (channel_type or "").strip().lower()
    webhook_url = (webhook_url or "").strip()
    secret = (secret or "").strip()

    if not name:
        raise ValueError("推送规则名称不能为空")
    if channel_type not in CHANNEL_LABELS:
        raise ValueError("推送通道不支持")
    if not webhook_url:
        raise ValueError("Webhook URL 不能为空")

    normalized_rules = _normalize_rule_items(rule_items or [])
    if not normalized_rules:
        raise ValueError("至少需要配置一条推送规则")

    config.name = name
    config.channel_type = channel_type
    config.enabled = bool(enabled)
    config.webhook_url = webhook_url
    if secret:
        config.secret = secret
    config.rule_items = normalized_rules
    db.session.commit()
    return _serialize_push_config(config, timezone_name=settings_service.get_timezone_name())


def toggle_push_config(config_id: int):
    config = db.session.get(PushConfig, config_id)
    if config is None:
        raise ValueError("推送配置不存在")
    config.enabled = not config.enabled
    db.session.commit()
    return _serialize_push_config(config, timezone_name=settings_service.get_timezone_name())


def delete_push_config(config_id: int):
    config = db.session.get(PushConfig, config_id)
    if config is None:
        raise ValueError("推送配置不存在")
    db.session.delete(config)
    db.session.commit()


def get_push_config(config_id: int):
    return db.session.get(PushConfig, config_id)


def matches_push_config(config, vulnerability):
    if not config.enabled:
        return False

    rule_items = _normalize_rule_items(config.rule_items or [])
    if not rule_items:
        return False

    affected_entries = None
    notification_type = str(getattr(vulnerability, "notification_type", "") or RULE_TYPE_VULNERABILITY).strip().lower()
    kev_indexed = _is_kev_indexed_vulnerability(vulnerability) if notification_type == RULE_TYPE_VULNERABILITY else False
    for rule in rule_items:
        rule_type = str((rule or {}).get("rule_type") or RULE_TYPE_VULNERABILITY).strip().lower()
        if rule_type == RULE_TYPE_GITHUB_TOOL:
            if notification_type != RULE_TYPE_GITHUB_TOOL:
                continue
            if _matches_github_tool_rule_item(rule, vulnerability):
                return True
            continue
        if notification_type != RULE_TYPE_VULNERABILITY:
            continue
        if _matches_vulnerability_rule_item(rule, vulnerability, affected_entries=affected_entries, kev_indexed=kev_indexed):
            return True
        if affected_entries is None:
            affected_entries = deserialize_affected_entries(
                vulnerability.affected_version_data,
                vulnerability.affected_versions or "",
            )
    return False


def migrate_legacy_push_configs():
    if PushConfig.query.first() is not None:
        return

    channels = {item.channel_type: item for item in PushChannel.query.all()}
    rules_by_type: dict[str, list] = {}
    for rule in PushRule.query.order_by(PushRule.id.asc()).all():
        rules_by_type.setdefault(rule.channel_type, []).append(rule)

    for channel_type in sorted(set(channels) | set(rules_by_type)):
        channel = channels.get(channel_type)
        legacy_rules = rules_by_type.get(channel_type, [])
        if not _should_migrate_legacy_channel(channel, legacy_rules):
            continue

        config = PushConfig(
            name=(channel.name if channel else CHANNEL_LABELS.get(channel_type, channel_type)) or channel_type,
            channel_type=channel_type,
            enabled=bool(channel.enabled) if channel is not None else True,
            webhook_url=(channel.webhook_url if channel is not None else "") or "",
            secret=(channel.secret if channel is not None else "") or "",
            rule_items=[_legacy_rule_to_item(item) for item in legacy_rules],
        )
        db.session.add(config)


def _serialize_push_config(config, timezone_name: str | None = None):
    payload = config.to_dict(timezone_name=timezone_name)
    rule_items = _normalize_rule_items(payload.get("rule_items") or [])
    payload["channel_name"] = CHANNEL_LABELS.get(config.channel_type, config.channel_type)
    payload["webhook_summary"] = _summarize_webhook(config.webhook_url)
    payload["rule_items"] = rule_items
    payload["rule_count"] = len(rule_items)
    payload["rule_summaries"] = [_rule_summary(item) for item in rule_items]
    return payload


def _normalize_rule_items(rule_items):
    output = []
    for item in rule_items:
        if not isinstance(item, dict):
            continue
        rule_type = (item.get("rule_type") or RULE_TYPE_VULNERABILITY).strip().lower()
        if rule_type == RULE_TYPE_GITHUB_TOOL:
            github_tool_status = _normalize_github_tool_status(item.get("status"))
            if github_tool_status == GITHUB_TOOL_ALL_STATUS:
                legacy_event_types = _normalize_github_tool_event_types(
                    item.get("event_types") or item.get("event_type")
                )
                if len(legacy_event_types) == 1:
                    github_tool_status = legacy_event_types[0]
            output.append(
                {
                    "rule_type": RULE_TYPE_GITHUB_TOOL,
                    "status": github_tool_status,
                }
            )
            continue
        if rule_type != RULE_TYPE_VULNERABILITY:
            continue
        sources = _normalize_rule_sources(item.get("sources"))
        if not sources:
            sources = _normalize_rule_sources(item.get("source"))
        severity_levels = _normalize_severity_levels(item.get("severity_levels"))
        severity_threshold = (item.get("severity_threshold") or "all").strip().lower()
        status = (item.get("status") or "all").strip().lower()
        nvd_vuln_statuses = _resolve_rule_nvd_vuln_statuses(item)
        products = _normalize_products(item.get("affected_products") or item.get("affected_products_text") or "")
        output.append(
            {
                "rule_type": RULE_TYPE_VULNERABILITY,
                "source": sources[0] if len(sources) == 1 else "all",
                "sources": sources,
                "severity_levels": severity_levels,
                "severity_threshold": severity_threshold or "all",
                "status": status or "all",
                "nvd_vuln_statuses": nvd_vuln_statuses,
                "affected_products": products,
            }
        )
    return output


def _normalize_products(value):
    if isinstance(value, list):
        lines = value
    else:
        lines = str(value or "").splitlines()
    normalized = []
    seen = set()
    for item in lines:
        text = (item or "").strip()
        lowered = text.lower()
        if not text or lowered in seen:
            continue
        seen.add(lowered)
        normalized.append(text)
    return normalized


def _matches_vulnerability_rule_item(rule, vulnerability, *, affected_entries=None, kev_indexed=False):
    current_severity = (vulnerability.severity or "unknown").lower()
    severity_levels = _normalize_severity_levels(rule.get("severity_levels"))
    if severity_levels:
        if current_severity not in severity_levels:
            return False
    else:
        threshold = (rule.get("severity_threshold") or "all").lower()
        if threshold != "all" and SEVERITY_RANK.get(current_severity, 0) < SEVERITY_RANK.get(threshold, 0):
            return False

    rule_sources = _normalize_rule_sources(rule.get("sources"))
    if not rule_sources:
        rule_sources = _normalize_rule_sources(rule.get("source"))
    normalized_rule_sources = {item.strip().lower() for item in rule_sources if item}
    vulnerability_source = (vulnerability.source or "").strip().lower()
    kev_selected = KEV_SOURCE_LABEL.lower() in normalized_rule_sources
    direct_source_match = vulnerability_source in normalized_rule_sources
    kev_source_match = kev_selected and kev_indexed
    if normalized_rule_sources and not direct_source_match and not kev_source_match:
        return False

    rule_status = (rule.get("status") or "all").strip().lower()
    vulnerability_status = (vulnerability.status or "").strip().lower()
    if rule_status != "all" and vulnerability_status != rule_status:
        return False

    rule_nvd_vuln_statuses = _resolve_rule_nvd_vuln_statuses(rule)
    if vulnerability_source == "nvd" and rule_nvd_vuln_statuses:
        vulnerability_nvd_vuln_status = _normalize_nvd_vuln_status(getattr(vulnerability, "vuln_status", None))
        if vulnerability_nvd_vuln_status not in rule_nvd_vuln_statuses:
            return False

    products = _normalize_products(rule.get("affected_products") or [])
    if products:
        entries = affected_entries
        if entries is None:
            entries = deserialize_affected_entries(
                vulnerability.affected_version_data,
                vulnerability.affected_versions or "",
            )
        if not any(matches_affected_filters(entries, product_keyword=item) for item in products):
            fallback_text = "\n".join(
                [
                    vulnerability.affected_products or "",
                    vulnerability.affected_versions or "",
                    vulnerability.description or "",
                ]
            ).lower()
            if not any(item.lower() in fallback_text for item in products):
                return False

    return True


def _matches_github_tool_rule_item(rule, github_tool_event):
    github_tool_status = _normalize_github_tool_status(rule.get("status"))
    if github_tool_status == GITHUB_TOOL_ALL_STATUS:
        legacy_event_types = _normalize_github_tool_event_types(rule.get("event_types") or rule.get("event_type"))
        if not legacy_event_types:
            return True
        current_event_type = str(getattr(github_tool_event, "event_type", "") or "").strip().lower()
        if not current_event_type:
            return False
        return current_event_type in legacy_event_types

    current_event_type = str(getattr(github_tool_event, "event_type", "") or "").strip().lower()
    if not current_event_type:
        return False
    return current_event_type == github_tool_status


def _should_migrate_legacy_channel(channel, legacy_rules):
    if legacy_rules:
        return True
    if channel is None:
        return False
    return bool(channel.enabled or channel.webhook_url or channel.secret)


def _legacy_rule_to_item(rule):
    return {
        "rule_type": RULE_TYPE_VULNERABILITY,
        "source": rule.source or "all",
        "sources": _normalize_rule_sources(rule.source),
        "severity_levels": [],
        "severity_threshold": (rule.severity_threshold or "all").lower(),
        "status": (rule.status or "all").lower(),
        "nvd_vuln_statuses": [],
        "affected_products": [],
    }


def _summarize_webhook(webhook_url: str) -> str:
    webhook_url = (webhook_url or "").strip()
    if not webhook_url:
        return "未配置"
    parsed = urlparse(webhook_url)
    host = parsed.netloc or webhook_url
    path = parsed.path or ""
    if len(path) > 20:
        path = f"{path[:20]}..."
    return f"{host}{path}"


def _rule_summary(rule):
    rule_type = str((rule or {}).get("rule_type") or RULE_TYPE_VULNERABILITY).strip().lower()
    if rule_type == RULE_TYPE_GITHUB_TOOL:
        github_tool_status = _normalize_github_tool_status(rule.get("status"))
        if github_tool_status == GITHUB_TOOL_ALL_STATUS:
            legacy_event_types = _normalize_github_tool_event_types(rule.get("event_types") or rule.get("event_type"))
            if not legacy_event_types:
                event_summary = "全部状态"
            else:
                event_summary = "、".join(GITHUB_TOOL_EVENT_LABELS.get(item, item) for item in legacy_event_types)
        else:
            event_summary = GITHUB_TOOL_EVENT_LABELS.get(github_tool_status, github_tool_status)
        return f"Github / {event_summary}"

    sources = _normalize_rule_sources(rule.get("sources"))
    if not sources:
        sources = _normalize_rule_sources(rule.get("source"))
    if not sources:
        source = "全部来源"
    elif len(sources) <= 2:
        source = "、".join(sources)
    else:
        source = "、".join(sources[:2]) + " 等"
    severity_levels = _normalize_severity_levels(rule.get("severity_levels"))
    if severity_levels:
        severity = "/".join(severity_levels)
    else:
        severity = "全部等级" if rule.get("severity_threshold") == "all" else rule.get("severity_threshold")
    status = "全部状态" if rule.get("status") == "all" else rule.get("status")
    nvd_vuln_statuses = _resolve_rule_nvd_vuln_statuses(rule)
    nvd_vuln_status_summary = ""
    if nvd_vuln_statuses and (not sources or any(item.strip().lower() == "nvd" for item in sources)):
        nvd_vuln_status_summary = " / NVD状态:" + "、".join(
            enum_label("vuln_status", item) for item in nvd_vuln_statuses
        )
    products = rule.get("affected_products") or []
    product_summary = "全部产品" if not products else "、".join(products[:3]) + (" 等" if len(products) > 3 else "")
    return f"漏洞 / {source} / {severity} / {status}{nvd_vuln_status_summary} / {product_summary}"


def _normalize_severity_levels(value):
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


def _normalize_rule_sources(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = [value]

    output = []
    seen = set()
    for item in items:
        text = str(item or "").strip()
        lowered = text.lower()
        if not text or lowered == "all" or lowered in seen:
            continue
        seen.add(lowered)
        output.append(text)
    return output


def _normalize_github_tool_event_types(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = [value]

    output = []
    seen = set()
    for item in items:
        normalized = str(item or "").strip().lower()
        if not normalized or normalized == "all" or normalized in seen:
            continue
        if normalized not in GITHUB_TOOL_EVENT_LABELS:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def _normalize_github_tool_status(value):
    normalized = str(value or "").strip().lower()
    if not normalized:
        return GITHUB_TOOL_ALL_STATUS
    if normalized in {GITHUB_TOOL_ALL_STATUS, *GITHUB_TOOL_EVENT_LABELS.keys()}:
        return normalized
    return GITHUB_TOOL_ALL_STATUS


def _is_kev_indexed_vulnerability(vulnerability) -> bool:
    cve_id = str(getattr(vulnerability, "cve_id", "") or "").strip().upper()
    if not cve_id:
        return False
    return KevCatalogEntry.query.filter_by(cve_id=cve_id).limit(1).first() is not None


def _normalize_nvd_vuln_status(value):
    text = str(value or "").strip()
    if not text:
        return "all"
    if text.lower() == "all":
        return "all"
    return text.upper()


def _normalize_nvd_vuln_statuses(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = [value]

    output = []
    seen = set()
    for item in items:
        normalized = _normalize_nvd_vuln_status(item)
        if normalized == "all" or normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def _resolve_rule_nvd_vuln_statuses(rule):
    statuses = _normalize_nvd_vuln_statuses(rule.get("nvd_vuln_statuses"))
    if statuses:
        return statuses
    if "nvd_vuln_statuses" in rule:
        return []
    legacy_status = _normalize_nvd_vuln_status(rule.get("nvd_vuln_status"))
    return [] if legacy_status == "all" else [legacy_status]
