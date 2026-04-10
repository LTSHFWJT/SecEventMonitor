from seceventmonitor.extensions import db
from seceventmonitor.models import PushChannel, PushRule
from seceventmonitor.services import settings as settings_service


SEVERITY_RANK = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def list_push_rules():
    timezone_name = settings_service.get_timezone_name()
    channels = {item.channel_type: item for item in PushChannel.query.all()}
    output = []
    for item in PushRule.query.order_by(PushRule.created_at.desc(), PushRule.id.desc()).all():
        payload = item.to_dict(timezone_name=timezone_name)
        payload["channel_name"] = channels.get(item.channel_type).name if channels.get(item.channel_type) else item.channel_type
        output.append(payload)
    return output


def list_enabled_push_rules():
    return PushRule.query.filter_by(enabled=True).order_by(PushRule.id.asc()).all()


def create_push_rule(
    name: str,
    channel_type: str,
    severity_threshold: str = "all",
    source: str = "all",
    status: str = "all",
    keyword: str = "",
    enabled: bool = True,
):
    name = (name or "").strip()
    channel_type = (channel_type or "").strip()
    severity_threshold = (severity_threshold or "all").strip().lower()
    source = (source or "all").strip()
    status = (status or "all").strip().lower()
    keyword = (keyword or "").strip()

    if not name:
        raise ValueError("规则名称不能为空")
    if not channel_type:
        raise ValueError("推送通道不能为空")
    channel = PushChannel.query.filter_by(channel_type=channel_type).first()
    if channel is None:
        raise ValueError("推送通道不存在")

    rule = PushRule(
        name=name,
        channel_type=channel_type,
        severity_threshold=severity_threshold,
        source=source or "all",
        status=status,
        keyword=keyword,
        enabled=bool(enabled),
    )
    db.session.add(rule)
    db.session.commit()
    return rule.to_dict(timezone_name=settings_service.get_timezone_name())


def toggle_push_rule(rule_id: int):
    rule = db.session.get(PushRule, rule_id)
    if rule is None:
        raise ValueError("推送规则不存在")
    rule.enabled = not rule.enabled
    db.session.commit()
    return rule.to_dict(timezone_name=settings_service.get_timezone_name())


def delete_push_rule(rule_id: int):
    rule = db.session.get(PushRule, rule_id)
    if rule is None:
        raise ValueError("推送规则不存在")
    db.session.delete(rule)
    db.session.commit()


def matches_push_rule(rule, vulnerability):
    if not rule.enabled:
        return False

    current_severity = (vulnerability.severity or "unknown").lower()
    threshold = (rule.severity_threshold or "all").lower()
    if threshold != "all" and SEVERITY_RANK.get(current_severity, 0) < SEVERITY_RANK.get(threshold, 0):
        return False

    rule_source = (rule.source or "all").strip().lower()
    vulnerability_source = (vulnerability.source or "").strip().lower()
    if rule_source != "all" and vulnerability_source != rule_source:
        return False

    rule_status = (rule.status or "all").strip().lower()
    vulnerability_status = (vulnerability.status or "").strip().lower()
    if rule_status != "all" and vulnerability_status != rule_status:
        return False

    keyword = (rule.keyword or "").strip().lower()
    if keyword:
        haystacks = [
            vulnerability.cve_id or "",
            vulnerability.title or "",
            vulnerability.description or "",
            vulnerability.reference_url or "",
        ]
        if not any(keyword in item.lower() for item in haystacks if item):
            return False

    return True
