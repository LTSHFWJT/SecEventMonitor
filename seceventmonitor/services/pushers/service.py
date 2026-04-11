import logging
import threading
from types import SimpleNamespace

from seceventmonitor.extensions import db
from seceventmonitor.models import PushLog
from seceventmonitor.services.push_config_service import (
    GITHUB_TOOL_EVENT_LABELS,
    RULE_TYPE_GITHUB_TOOL,
    RULE_TYPE_VULNERABILITY,
    get_push_config,
    list_enabled_push_configs,
    matches_push_config,
)
from seceventmonitor.services.pushers import DingTalkPusher, LarkPusher
from seceventmonitor.services.settings import get_settings_map, get_timezone_name
from seceventmonitor.utils.enum_labels import SEVERITY_LABELS, STATUS_LABELS
from seceventmonitor.utils.timezone import format_datetime

logger = logging.getLogger(__name__)
PUSH_LINE_BREAK = "\n"


def build_pusher(config):
    proxy_url = get_settings_map().get("http_proxy", "")
    if config.channel_type == "dingding":
        return DingTalkPusher(config.webhook_url, config.secret, proxy_url=proxy_url)
    if config.channel_type == "lark":
        return LarkPusher(config.webhook_url, config.secret, proxy_url=proxy_url)
    raise ValueError("暂不支持该推送通道")


def notify_vulnerability(vulnerability):
    enabled_configs = list_enabled_push_configs()
    if not enabled_configs:
        return 0

    matched_configs = _resolve_target_configs(vulnerability, enabled_configs)
    if not matched_configs:
        return 0

    success_count = 0
    title, content = render_vulnerability_message(vulnerability)
    for config in matched_configs:
        title, content = render_vulnerability_message(vulnerability)
        success_count += _push_with_log(
            config=config,
            vulnerability_id=vulnerability.id,
            title=title,
            content=content,
        )
    return success_count


def notify_github_tool_event(github_tool_event):
    enabled_configs = list_enabled_push_configs()
    if not enabled_configs:
        return 0

    matched_configs = _resolve_target_configs(github_tool_event, enabled_configs)
    if not matched_configs:
        return 0

    success_count = 0
    title, content = render_github_tool_message(github_tool_event)
    github_tool_id = getattr(github_tool_event, "github_tool_id", None) or getattr(github_tool_event, "id", None)
    for config in matched_configs:
        title, content = render_github_tool_message(github_tool_event)
        success_count += _push_with_log(
            config=config,
            vulnerability_id=None,
            github_tool_id=github_tool_id,
            title=title,
            content=content,
        )
    return success_count


def notify_github_poc_event(github_poc_event):
    enabled_configs = list_enabled_push_configs()
    if not enabled_configs:
        return 0

    matched_configs = _resolve_target_configs(github_poc_event, enabled_configs)
    if not matched_configs:
        return 0

    success_count = 0
    title, content = render_github_poc_message(github_poc_event)
    github_poc_id = getattr(github_poc_event, "github_poc_id", None) or getattr(github_poc_event, "id", None)
    for config in matched_configs:
        title, content = render_github_poc_message(github_poc_event)
        success_count += _push_with_log(
            config=config,
            vulnerability_id=None,
            github_poc_id=github_poc_id,
            title=title,
            content=content,
        )
    return success_count


def dispatch_vulnerability_notifications(notification_targets):
    targets = [item for item in notification_targets if isinstance(item, dict) and item.get("id")]
    if not targets:
        return 0

    worker = threading.Thread(
        target=_dispatch_vulnerability_notifications_worker,
        args=(targets,),
        name=f"push-{targets[0]['id']}",
        daemon=True,
    )
    worker.start()
    return len(targets)


def dispatch_github_tool_notifications(notification_targets):
    targets = [item for item in notification_targets if isinstance(item, dict) and item.get("id")]
    if not targets:
        return 0

    worker = threading.Thread(
        target=_dispatch_github_tool_notifications_worker,
        args=(targets,),
        name=f"github-push-{targets[0]['id']}",
        daemon=True,
    )
    worker.start()
    return len(targets)


def dispatch_github_poc_notifications(notification_targets):
    targets = [item for item in notification_targets if isinstance(item, dict) and item.get("id")]
    if not targets:
        return 0

    worker = threading.Thread(
        target=_dispatch_github_poc_notifications_worker,
        args=(targets,),
        name=f"github-poc-push-{targets[0]['id']}",
        daemon=True,
    )
    worker.start()
    return len(targets)


def send_test_message(config_id, message=""):
    config = get_push_config(config_id)
    if config is None:
        raise ValueError("推送配置不存在")
    return send_test_message_with_payload(
        channel_type=config.channel_type,
        webhook_url=config.webhook_url,
        secret=config.secret,
        message=message,
        push_config_id=config.id,
    )


def send_test_message_with_payload(
    *,
    channel_type,
    webhook_url,
    secret="",
    message="",
    push_config_id=None,
):
    config = _build_temp_config(
        channel_type=channel_type,
        webhook_url=webhook_url,
        secret=secret,
        push_config_id=push_config_id,
    )
    if not config.webhook_url:
        raise ValueError("请先配置 webhook")

    title = "SecEventMonitor 测试消息"
    content = message.strip() or PUSH_LINE_BREAK.join(
        [
            "当前为通道连通性测试。",
            "如果你收到这条消息，说明机器人 webhook 与签名配置有效。",
            f"通道类型: {config.channel_type}",
        ]
    )
    success_count = _push_with_log(
        config=config,
        vulnerability_id=None,
        title=title,
        content=content,
        raise_on_error=True,
    )
    if success_count == 0:
        raise RuntimeError("测试发送失败")
    return {"config_id": getattr(config, "id", None), "message": "测试发送成功"}


def render_vulnerability_message(vulnerability):
    identity = vulnerability.cve_id or vulnerability.title or "漏洞事件"
    title = f"[{vulnerability.source}] {identity}"
    severity = (vulnerability.severity or "").strip().lower()
    status = (vulnerability.status or "").strip().lower()
    translated_description = (
        getattr(vulnerability, "translated_description", None)
        or getattr(vulnerability, "description", None)
        or ""
    )
    translated_remediation = (
        getattr(vulnerability, "translated_remediation", None)
        or getattr(vulnerability, "remediation", None)
        or ""
    )
    affected_versions = (getattr(vulnerability, "affected_versions", None) or "").strip() or "-"
    lines = [
        f"等级：{SEVERITY_LABELS.get(severity, vulnerability.severity or '-')}",
        f"来源：{vulnerability.source}",
        f"状态：{STATUS_LABELS.get(status, vulnerability.status or '-')}",
        f"受影响版本：{_normalize_push_text(affected_versions) or '-'}",
        f"解决方案：{_normalize_push_text(translated_remediation) or '-'}",
        f"简介：{_normalize_push_text(translated_description) or '-'}",
    ]
    return title, PUSH_LINE_BREAK.join(lines)


def render_github_tool_message(github_tool_event):
    event_type = str(getattr(github_tool_event, "event_type", "") or "").strip().lower()
    event_label = GITHUB_TOOL_EVENT_LABELS.get(event_type, event_type or "-")
    repo_full_name = str(getattr(github_tool_event, "repo_full_name", "") or "").strip()
    tool_name = str(getattr(github_tool_event, "tool_name", "") or "").strip() or repo_full_name or "GitHub 仓库"
    current_version = str(getattr(github_tool_event, "version", "") or "").strip() or "-"
    previous_version = str(getattr(github_tool_event, "previous_version", "") or "").strip()
    repo_url = str(getattr(github_tool_event, "repo_url", "") or "").strip() or "-"
    repo_updated_at = format_datetime(
        getattr(github_tool_event, "repo_updated_at", None),
        timezone_name=get_timezone_name(),
    ) or "-"

    version_text = current_version
    if event_type == "version_updated" and previous_version and previous_version != current_version:
        version_text = f"{previous_version} -> {current_version}"

    title = f"[GitHub监控] {tool_name}"
    lines = [
        f"事件：{event_label}",
        f"工具名称：{tool_name}",
        f"仓库：{repo_full_name or '-'}",
        f"版本：{version_text}",
        f"最近版本发布时间：{repo_updated_at}",
        f"链接：{repo_url}",
    ]
    return title, PUSH_LINE_BREAK.join(lines)


def render_github_poc_message(github_poc_event):
    event_type = str(getattr(github_poc_event, "event_type", "") or "").strip().lower()
    event_label = GITHUB_TOOL_EVENT_LABELS.get(event_type, event_type or "-")
    cve_id = str(getattr(github_poc_event, "cve_id", "") or "").strip() or "-"
    repo_full_name = str(getattr(github_poc_event, "repo_full_name", "") or "").strip() or "-"
    owner_login = str(getattr(github_poc_event, "owner_login", "") or "").strip() or "-"
    description = str(getattr(github_poc_event, "description", "") or "").strip() or "-"
    repo_url = str(getattr(github_poc_event, "repo_url", "") or "").strip() or "-"
    repo_updated_at = format_datetime(
        getattr(github_poc_event, "repo_updated_at", None),
        timezone_name=get_timezone_name(),
    ) or "-"

    title = f"[POC监控] {cve_id}"
    lines = [
        f"事件：{event_label}",
        f"CVE编号：{cve_id}",
        f"PoC仓库：{repo_full_name}",
        f"作者：{owner_login}",
        f"最近更新时间：{repo_updated_at}",
        f"简介：{_normalize_push_text(description) or '-'}",
        f"链接：{repo_url}",
    ]
    return title, PUSH_LINE_BREAK.join(lines)


def _resolve_target_configs(vulnerability, enabled_configs):
    matched = []
    for config in enabled_configs:
        if matches_push_config(config, vulnerability):
            matched.append(config)
    return matched


def _dispatch_vulnerability_notifications_worker(targets):
    try:
        for payload in targets:
            try:
                vulnerability = SimpleNamespace(notification_type=RULE_TYPE_VULNERABILITY, **payload)
                notify_vulnerability(vulnerability)
                db.session.commit()
            except Exception:
                db.session.rollback()
                logger.exception("failed to deliver async notification for vulnerability %s", payload.get("id"))
    finally:
        db.remove()


def _dispatch_github_tool_notifications_worker(targets):
    try:
        for payload in targets:
            try:
                github_tool_event = SimpleNamespace(notification_type=RULE_TYPE_GITHUB_TOOL, **payload)
                notify_github_tool_event(github_tool_event)
                db.session.commit()
            except Exception:
                db.session.rollback()
                logger.exception("failed to deliver async notification for github tool %s", payload.get("id"))
    finally:
        db.remove()


def _dispatch_github_poc_notifications_worker(targets):
    try:
        for payload in targets:
            try:
                github_poc_event = SimpleNamespace(notification_type=RULE_TYPE_GITHUB_TOOL, **payload)
                notify_github_poc_event(github_poc_event)
                db.session.commit()
            except Exception:
                db.session.rollback()
                logger.exception("failed to deliver async notification for github poc %s", payload.get("id"))
    finally:
        db.remove()


def _push_with_log(
    config,
    vulnerability_id,
    title,
    content,
    github_tool_id=None,
    github_poc_id=None,
    raise_on_error=False,
):
    pusher = build_pusher(config)
    push_log = PushLog(
        push_config_id=getattr(config, "id", None),
        vulnerability_id=vulnerability_id,
        github_tool_id=github_tool_id,
        github_poc_id=github_poc_id,
        status="pending",
        message="准备发送",
    )
    db.session.add(push_log)
    db.session.flush()

    try:
        payload = pusher.push_message(title, content)
        push_log.status = "success"
        push_log.message = str(payload)
        return 1
    except Exception as exc:
        push_log.status = "failed"
        push_log.message = str(exc)
        if raise_on_error:
            raise
        return 0


def _build_temp_config(*, channel_type, webhook_url, secret="", push_config_id=None):
    channel_type = (channel_type or "").strip().lower()
    if channel_type not in {"dingding", "lark"}:
        raise ValueError("推送通道不支持")
    return type(
        "TempPushConfig",
        (),
        {
            "id": push_config_id,
            "enabled": True,
            "channel_type": channel_type,
            "webhook_url": (webhook_url or "").strip(),
            "secret": (secret or "").strip(),
        },
    )()


def _normalize_push_text(value):
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return PUSH_LINE_BREAK.join(line.rstrip() for line in text.split("\n"))
