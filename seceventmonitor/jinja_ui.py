from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from seceventmonitor.config import Config
from seceventmonitor.extensions import db
from seceventmonitor.models import GithubPocEntry, Vulnerability
from seceventmonitor.services.collectors import list_supported_vulnerability_sources
from seceventmonitor.services import settings as settings_service
from seceventmonitor.services.admin_service import (
    authenticate_admin,
    get_admin_by_id,
    initialize_admin,
    is_initialized,
    update_admin_password,
    update_admin_username,
)
from seceventmonitor.services.github_api_service import (
    create_github_api_config,
    delete_github_api_config,
    list_github_api_configs_paginated,
    toggle_github_api_config,
    update_github_api_config,
)
from seceventmonitor.services.github_poc_service import list_github_poc_entries_paginated
from seceventmonitor.services.github_monitor_service import (
    delete_github_monitored_tool,
    import_github_monitored_tools,
    list_github_monitored_tools_paginated,
    update_github_monitored_tool,
)
from seceventmonitor.services.monitor_service import (
    create_rule,
    delete_rule,
    get_overview,
    get_vulnerability_filter_options,
    list_rules,
    list_sync_jobs_paginated,
    list_vulnerabilities_paginated,
    update_rule,
)
from seceventmonitor.services.push_config_service import (
    CHANNEL_LABELS,
    GITHUB_TOOL_EVENT_LABELS,
    RULE_TYPE_GITHUB_TOOL,
    RULE_TYPE_VULNERABILITY,
    create_push_config,
    delete_push_config,
    get_push_config,
    list_push_configs_paginated,
    toggle_push_config,
    update_push_config,
)
from seceventmonitor.services.pushers.service import send_test_message, send_test_message_with_payload
from seceventmonitor.services.scheduler_service import reload_scheduler
from seceventmonitor.services.sync_service import get_sync_source_options, list_active_sync_jobs, start_sync_async
from seceventmonitor.services.translation_api_service import (
    create_translation_api_config,
    delete_translation_api_config,
    list_translation_api_configs_paginated,
    toggle_translation_api_config,
    update_translation_api_config,
)
from seceventmonitor.utils.enum_labels import SEVERITY_LABELS, STATUS_LABELS, enum_label


BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def register_jinja_ui(app: FastAPI) -> None:
    static_dir = BASE_DIR / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    async def root(request: Request):
        if not is_initialized():
            return RedirectResponse(url="/setup", status_code=303)
        if _get_current_admin(request) is None:
            return RedirectResponse(url="/login", status_code=303)
        return RedirectResponse(url="/overview", status_code=303)

    @app.get("/setup", response_class=HTMLResponse, include_in_schema=False)
    async def setup_page(request: Request):
        if is_initialized():
            if _get_current_admin(request) is not None:
                return RedirectResponse(url="/overview", status_code=303)
            return RedirectResponse(url="/login", status_code=303)
        return _render(request, "public/setup.html", title="初始化", admin=None)

    @app.post("/setup", response_class=HTMLResponse, include_in_schema=False)
    async def setup_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        confirm_password: str = Form(...),
    ):
        if is_initialized():
            return RedirectResponse(url="/login", status_code=303)
        try:
            if password != confirm_password:
                raise ValueError("两次输入的密码不一致")
            admin = initialize_admin(username, password)
            request.session[Config.ADMIN_SESSION_KEY] = admin.id
            _set_flash(request, "初始化完成", "success")
            return RedirectResponse(url="/overview", status_code=303)
        except Exception as exc:
            db.session.rollback()
            return _render(
                request,
                "public/setup.html",
                title="初始化",
                admin=None,
                error=str(exc),
                form_data={
                    "username": username,
                },
                status_code=400,
            )
        finally:
            db.remove()

    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    async def login_page(request: Request):
        if not is_initialized():
            return RedirectResponse(url="/setup", status_code=303)
        if _get_current_admin(request) is not None:
            return RedirectResponse(url="/overview", status_code=303)
        return _render(request, "public/login.html", title="登录", admin=None)

    @app.post("/login", response_class=HTMLResponse, include_in_schema=False)
    async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ):
        if not is_initialized():
            return RedirectResponse(url="/setup", status_code=303)
        try:
            admin = authenticate_admin(username, password)
            request.session[Config.ADMIN_SESSION_KEY] = admin.id
            _set_flash(request, "登录成功", "success")
            return RedirectResponse(url="/overview", status_code=303)
        except Exception as exc:
            db.session.rollback()
            return _render(
                request,
                "public/login.html",
                title="登录",
                admin=None,
                error=str(exc),
                form_data={"username": username},
                status_code=400,
            )
        finally:
            db.remove()

    @app.post("/logout", include_in_schema=False)
    async def logout(request: Request):
        request.session.clear()
        response = RedirectResponse(url="/login", status_code=303)
        return response

    @app.get("/overview", response_class=HTMLResponse, include_in_schema=False)
    async def overview_page(request: Request):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        data = get_overview()
        return _render(
            request,
            "admin/overview.html",
            title="概览",
            admin=admin,
            current_nav="overview",
            overview=data,
        )

    @app.get("/monitor", response_class=HTMLResponse, include_in_schema=False)
    async def monitor_page(
        request: Request,
        page: int = 1,
        page_size: int = 10,
        keyword: str = "",
        source: str = "all",
        status: str = "all",
        affected_product: str = "",
        affected_version: str = "",
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)

        severity = request.query_params.getlist("severity")
        vulnerability_page = list_vulnerabilities_paginated(
            page=page,
            page_size=page_size,
            keyword=keyword,
            severity=severity,
            source=source,
            status=status,
            affected_product=affected_product,
            affected_version=affected_version,
        )
        filters = get_vulnerability_filter_options()
        return _render(
            request,
            "admin/monitor.html",
            title="漏洞列表",
            admin=admin,
            current_nav="monitor",
            vulnerability_page=vulnerability_page,
            filter_options=filters,
            filter_state={
                "keyword": keyword,
                "severity": severity,
                "source": source,
                "status": status,
                "page_size": page_size,
                "affected_product": affected_product,
                "affected_version": affected_version,
            },
            pagination_query=urlencode(
                {
                    "keyword": keyword,
                    "severity": severity,
                    "source": source,
                    "status": status,
                    "page_size": page_size,
                    "affected_product": affected_product,
                    "affected_version": affected_version,
                },
                doseq=True,
            ),
            pagination_pages=_build_pagination_pages(
                vulnerability_page["page"],
                vulnerability_page["total_pages"],
            ),
        )

    @app.get("/redteam-github/tools", response_class=HTMLResponse, include_in_schema=False)
    async def redteam_tools_page(request: Request, page: int = 1, page_size: int = 10, keyword: str = ""):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        tool_page = list_github_monitored_tools_paginated(
            page=page,
            page_size=page_size,
            keyword=keyword,
        )
        return _render(
            request,
            "admin/redteam_tools.html",
            title="红队工具",
            admin=admin,
            current_nav="redteam_tools",
            tool_page=tool_page,
            filter_state={
                "keyword": keyword,
                "page_size": page_size,
            },
            pagination_query=urlencode(
                {
                    "keyword": keyword,
                    "page_size": page_size,
                }
            ),
            pagination_pages=_build_pagination_pages(
                tool_page["page"],
                tool_page["total_pages"],
            ),
        )

    @app.get("/redteam-github/pocs", response_class=HTMLResponse, include_in_schema=False)
    async def github_pocs_page(
        request: Request,
        page: int = 1,
        page_size: int = 10,
        keyword: str = "",
        status: str = "all",
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        poc_page = list_github_poc_entries_paginated(
            page=page,
            page_size=page_size,
            keyword=keyword,
            status=status,
        )
        return _render(
            request,
            "admin/github_pocs.html",
            title="POC监控",
            admin=admin,
            current_nav="github_pocs",
            poc_page=poc_page,
            poc_status_options=["all", "new", "updated"],
            filter_state={
                "keyword": keyword,
                "status": status,
                "page_size": page_size,
            },
            pagination_query=urlencode(
                {
                    "keyword": keyword,
                    "status": status,
                    "page_size": page_size,
                }
            ),
            pagination_pages=_build_pagination_pages(
                poc_page["page"],
                poc_page["total_pages"],
            ),
        )

    @app.get("/redteam-github/pocs/{poc_id}", response_class=HTMLResponse, include_in_schema=False)
    async def github_poc_detail_page(request: Request, poc_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        poc_entry = db.session.get(GithubPocEntry, poc_id)
        if poc_entry is None:
            _set_flash(request, "POC 记录不存在", "error")
            return RedirectResponse(url="/redteam-github/pocs", status_code=303)
        return _render(
            request,
            "admin/github_poc_detail.html",
            title=poc_entry.cve_id or "POC详情",
            admin=admin,
            current_nav="github_pocs",
            github_poc=poc_entry.to_dict(timezone_name=settings_service.get_timezone_name()),
        )

    @app.post("/redteam-github/tools", include_in_schema=False)
    async def redteam_tools_import_submit(
        request: Request,
        repo_links: str = Form(""),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            result = import_github_monitored_tools(repo_links)
            messages = []
            if result["created"]:
                messages.append(f"新增 {result['created']} 条")
            if result["updated"]:
                messages.append(f"已存在 {result['updated']} 条")
            if result.get("queued"):
                messages.append(f"后台刷新 {result['queued']} 条")
            if result.get("invalid_count"):
                messages.append(f"忽略 {result['invalid_count']} 条无效链接")
            if not messages:
                messages.append("没有可导入的仓库")
            _set_flash(request, "，".join(messages), "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/redteam-github/tools", status_code=303)

    @app.post("/redteam-github/tools/{tool_id}/update", include_in_schema=False)
    async def redteam_tools_update_submit(
        request: Request,
        tool_id: int,
        repo_url: str = Form(...),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            update_github_monitored_tool(tool_id, repo_url=repo_url)
            _set_flash(request, "GitHub 监控仓库已保存，后台正在刷新数据", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/redteam-github/tools", status_code=303)

    @app.post("/redteam-github/tools/{tool_id}/delete", include_in_schema=False)
    async def redteam_tools_delete_submit(request: Request, tool_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            delete_github_monitored_tool(tool_id)
            _set_flash(request, "GitHub 监控仓库已删除", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/redteam-github/tools", status_code=303)

    @app.get("/monitor-config", response_class=HTMLResponse, include_in_schema=False)
    async def monitor_config_page(request: Request, log_page: int = 1, log_page_size: int = 10):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        sync_job_page = list_sync_jobs_paginated(page=log_page, page_size=log_page_size)
        return _render(
            request,
            "admin/monitor_config.html",
            title="监控配置",
            admin=admin,
            current_nav="monitor_config",
            settings_map=settings_service.get_settings_map(),
            sync_source_options=get_sync_source_options(),
            active_jobs=list_active_sync_jobs(limit=10),
            sync_job_page=sync_job_page,
            sync_pagination_query=urlencode({"log_page_size": log_page_size}),
            sync_pagination_pages=_build_pagination_pages(
                sync_job_page["page"],
                sync_job_page["total_pages"],
            ),
        )

    @app.post("/monitor-config/settings", include_in_schema=False)
    async def monitor_config_settings_submit(
        request: Request,
        monitor_interval_minutes: str = Form("60"),
        github_monitor_interval_minutes: str = Form("60"),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            settings_service.update_settings(
                {
                    "monitor_interval_minutes": monitor_interval_minutes,
                    "github_monitor_interval_minutes": github_monitor_interval_minutes,
                }
            )
            db.session.commit()
            reload_scheduler()
            _set_flash(request, "监控配置已保存", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/monitor-config", status_code=303)

    @app.get("/api-config/nvd", response_class=HTMLResponse, include_in_schema=False)
    async def nvd_api_config_page(request: Request):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        return _render(
            request,
            "admin/nvd_api_config.html",
            title="NVD API Key",
            admin=admin,
            current_nav="api_config_nvd",
            settings_map=settings_service.get_settings_map(),
        )

    @app.post("/api-config/nvd", include_in_schema=False)
    async def nvd_api_config_submit(
        request: Request,
        nvd_api_key: str = Form(""),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            settings_service.update_settings(
                {
                    "nvd_api_key": nvd_api_key,
                }
            )
            db.session.commit()
            _set_flash(request, "NVD API Key 已保存", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/api-config/nvd", status_code=303)

    @app.get("/api-config/github", response_class=HTMLResponse, include_in_schema=False)
    async def github_api_page(request: Request, page: int = 1, page_size: int = 10):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        github_api_page = list_github_api_configs_paginated(page=page, page_size=page_size)
        return _render(
            request,
            "admin/github_api.html",
            title="GitHub API",
            admin=admin,
            current_nav="api_config_github",
            github_api_page=github_api_page,
            pagination_query=urlencode({"page_size": page_size}),
            pagination_pages=_build_pagination_pages(
                github_api_page["page"],
                github_api_page["total_pages"],
            ),
        )

    @app.post("/api-config/github/configs", include_in_schema=False)
    async def github_api_submit(
        request: Request,
        name: str = Form(...),
        api_token: str = Form(...),
        enabled: str | None = Form(default=None),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            create_github_api_config(
                name=name,
                api_token=api_token,
                enabled=enabled is not None,
            )
            _set_flash(request, "GitHub API 配置已创建", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/api-config/github", status_code=303)

    @app.post("/api-config/github/configs/{config_id}/update", include_in_schema=False)
    async def github_api_update_submit(
        request: Request,
        config_id: int,
        name: str = Form(...),
        api_token: str = Form(""),
        enabled: str | None = Form(default=None),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            update_github_api_config(
                config_id,
                name=name,
                api_token=api_token,
                enabled=enabled is not None,
            )
            _set_flash(request, "GitHub API 配置已更新", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/api-config/github", status_code=303)

    @app.post("/api-config/github/configs/{config_id}/toggle", include_in_schema=False)
    async def github_api_toggle_submit(request: Request, config_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            toggle_github_api_config(config_id)
            _set_flash(request, "GitHub API 配置状态已更新", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/api-config/github", status_code=303)

    @app.post("/api-config/github/configs/{config_id}/delete", include_in_schema=False)
    async def github_api_delete_submit(request: Request, config_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            delete_github_api_config(config_id)
            _set_flash(request, "GitHub API 配置已删除", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/api-config/github", status_code=303)

    @app.get("/monitor/vulnerability/{vulnerability_id}", response_class=HTMLResponse, include_in_schema=False)
    async def vulnerability_detail_page(request: Request, vulnerability_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        vulnerability = db.session.get(Vulnerability, vulnerability_id)
        if vulnerability is None:
            _set_flash(request, "漏洞不存在", "error")
            return RedirectResponse(url="/monitor", status_code=303)
        return _render(
            request,
            "admin/vulnerability_detail.html",
            title=vulnerability.display_identifier or vulnerability.cve_id or "漏洞详情",
            admin=admin,
            current_nav="monitor",
            vulnerability=vulnerability.to_dict(timezone_name=settings_service.get_timezone_name()),
        )

    @app.post("/monitor/sync", include_in_schema=False)
    async def monitor_sync(request: Request):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            form = await request.form()
            selected_sources = form.getlist("source")
            result = start_sync_async(source=selected_sources)
            _set_flash(request, result.get("message", "同步任务已启动"), "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/monitor-config", status_code=303)

    @app.post("/rules", include_in_schema=False)
    async def create_rule_submit(
        request: Request,
        name: str = Form(...),
        rule_type: str = Form(...),
        target: str = Form(...),
        description: str = Form(""),
        enabled: str | None = Form(default=None),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            create_rule(
                name=name,
                rule_type=rule_type,
                target=target,
                description=description,
                enabled=enabled is not None,
            )
            _set_flash(request, "规则已创建", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/monitor-config", status_code=303)

    @app.post("/rules/{rule_id}/toggle", include_in_schema=False)
    async def toggle_rule_submit(request: Request, rule_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            rules = list_rules()
            current = next((item for item in rules if item["id"] == rule_id), None)
            if current is None:
                raise ValueError("规则不存在")
            update_rule(rule_id, enabled=not current["enabled"])
            _set_flash(request, "规则状态已更新", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/monitor-config", status_code=303)

    @app.post("/rules/{rule_id}/delete", include_in_schema=False)
    async def delete_rule_submit(request: Request, rule_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            delete_rule(rule_id)
            _set_flash(request, "规则已删除", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/monitor-config", status_code=303)

    @app.get("/push", response_class=HTMLResponse, include_in_schema=False)
    async def push_page(request: Request, page: int = 1, page_size: int = 10):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        push_config_page = list_push_configs_paginated(page=page, page_size=page_size)
        filter_options = get_vulnerability_filter_options()
        return _render(
            request,
            "admin/push.html",
            title="推送配置",
            admin=admin,
            current_nav="push",
            push_config_page=push_config_page,
            push_form_options={
                "channels": [{"value": key, "label": value} for key, value in CHANNEL_LABELS.items()],
                "rule_types": [
                    {"value": RULE_TYPE_VULNERABILITY, "label": "漏洞"},
                    {"value": RULE_TYPE_GITHUB_TOOL, "label": "Github"},
                ],
                "severities": filter_options["severities"],
                "statuses": ["all", *[item for item in filter_options["statuses"] if item != "all"]],
                "sources": _build_push_rule_source_options(filter_options["sources"]),
                "nvd_vuln_statuses": _build_nvd_vuln_status_options(),
                "github_statuses": [{"value": "all", "label": "全部状态"}]
                + [{"value": key, "label": value} for key, value in GITHUB_TOOL_EVENT_LABELS.items()],
            },
            pagination_query=urlencode({"page_size": page_size}),
            pagination_pages=_build_pagination_pages(
                push_config_page["page"],
                push_config_page["total_pages"],
            ),
        )

    @app.post("/push/configs", include_in_schema=False)
    async def push_config_submit(
        request: Request,
        name: str = Form(...),
        channel_type: str = Form(...),
        webhook_url: str = Form(...),
        secret: str = Form(""),
        enabled: str | None = Form(default=None),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            form = await request.form()
            rule_items = _extract_push_rule_items(form)
            create_push_config(
                name=name,
                channel_type=channel_type,
                webhook_url=webhook_url,
                secret=secret,
                enabled=enabled is not None,
                rule_items=rule_items,
            )
            _set_flash(request, "推送配置已创建", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/push", status_code=303)

    @app.post("/push/configs/{config_id}/update", include_in_schema=False)
    async def push_config_update_submit(
        request: Request,
        config_id: int,
        name: str = Form(...),
        channel_type: str = Form(...),
        webhook_url: str = Form(...),
        secret: str = Form(""),
        enabled: str | None = Form(default=None),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            form = await request.form()
            rule_items = _extract_push_rule_items(form)
            update_push_config(
                config_id,
                name=name,
                channel_type=channel_type,
                webhook_url=webhook_url,
                secret=secret,
                enabled=enabled is not None,
                rule_items=rule_items,
            )
            _set_flash(request, "推送配置已更新", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/push", status_code=303)

    @app.post("/push/configs/test", include_in_schema=False)
    async def push_config_form_test_submit(
        request: Request,
        channel_type: str = Form(...),
        webhook_url: str = Form(""),
        secret: str = Form(""),
        config_id: int | None = Form(default=None),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            existing_config = get_push_config(config_id) if config_id else None
            if config_id and existing_config is None:
                raise ValueError("推送配置不存在")
            send_test_message_with_payload(
                channel_type=channel_type or (existing_config.channel_type if existing_config else ""),
                webhook_url=webhook_url or (existing_config.webhook_url if existing_config else ""),
                secret=secret or (existing_config.secret if existing_config else ""),
                push_config_id=config_id,
            )
            db.session.commit()
            if _wants_json_response(request):
                return JSONResponse({"status": "success", "message": "测试消息已发送"})
            _set_flash(request, "测试消息已发送", "success")
        except Exception as exc:
            db.session.rollback()
            if _wants_json_response(request):
                return JSONResponse({"status": "error", "message": str(exc)}, status_code=400)
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/push", status_code=303)

    @app.post("/push/configs/{config_id}/test", include_in_schema=False)
    async def push_test_submit(request: Request, config_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            send_test_message(config_id)
            db.session.commit()
            _set_flash(request, "测试消息已发送", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/push", status_code=303)

    @app.post("/push/configs/{config_id}/toggle", include_in_schema=False)
    async def push_config_toggle_submit(request: Request, config_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            toggle_push_config(config_id)
            _set_flash(request, "推送配置状态已更新", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/push", status_code=303)

    @app.post("/push/configs/{config_id}/delete", include_in_schema=False)
    async def push_config_delete_submit(request: Request, config_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            delete_push_config(config_id)
            _set_flash(request, "推送配置已删除", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/push", status_code=303)

    @app.get("/translation-api", response_class=HTMLResponse, include_in_schema=False)
    async def translation_api_page(request: Request, page: int = 1, page_size: int = 10):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        translation_page = list_translation_api_configs_paginated(page=page, page_size=page_size)
        return _render(
            request,
            "admin/translation_api.html",
            title="翻译API",
            admin=admin,
            current_nav="translation_api",
            translation_page=translation_page,
            pagination_query=urlencode({"page_size": page_size}),
            pagination_pages=_build_pagination_pages(
                translation_page["page"],
                translation_page["total_pages"],
            ),
        )

    @app.post("/translation-api/configs", include_in_schema=False)
    async def translation_api_submit(
        request: Request,
        app_id: str = Form(...),
        api_key: str = Form(...),
        enabled: str | None = Form(default=None),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            create_translation_api_config(
                app_id=app_id,
                api_key=api_key,
                enabled=enabled is not None,
            )
            _set_flash(request, "翻译 API 配置已创建", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/translation-api", status_code=303)

    @app.post("/translation-api/configs/{config_id}/update", include_in_schema=False)
    async def translation_api_update_submit(
        request: Request,
        config_id: int,
        app_id: str = Form(...),
        api_key: str = Form(""),
        enabled: str | None = Form(default=None),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            update_translation_api_config(
                config_id,
                app_id=app_id,
                api_key=api_key,
                enabled=enabled is not None,
            )
            _set_flash(request, "翻译 API 配置已更新", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/translation-api", status_code=303)

    @app.post("/translation-api/configs/{config_id}/toggle", include_in_schema=False)
    async def translation_api_toggle_submit(request: Request, config_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            toggle_translation_api_config(config_id)
            _set_flash(request, "翻译 API 配置状态已更新", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/translation-api", status_code=303)

    @app.post("/translation-api/configs/{config_id}/delete", include_in_schema=False)
    async def translation_api_delete_submit(request: Request, config_id: int):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            delete_translation_api_config(config_id)
            _set_flash(request, "翻译 API 配置已删除", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/translation-api", status_code=303)

    @app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
    async def settings_page(request: Request):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        settings_map = settings_service.get_settings_map()
        return _render(
            request,
            "admin/settings.html",
            title="系统设置",
            admin=admin,
            current_nav="settings",
            settings_map=settings_map,
        )

    @app.post("/settings", include_in_schema=False)
    async def settings_submit(
        request: Request,
        timezone: str = Form("Asia/Shanghai"),
        http_proxy: str = Form(""),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            settings_service.update_settings(
                {
                    "timezone": timezone,
                    "http_proxy": http_proxy,
                }
            )
            db.session.commit()
            _set_flash(request, "系统设置已保存", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/settings", status_code=303)

    @app.post("/settings/account/username", include_in_schema=False)
    async def settings_account_username_submit(
        request: Request,
        username: str = Form(...),
        current_password: str = Form(...),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            update_admin_username(
                admin.id,
                username=username,
                current_password=current_password,
            )
            _set_flash(request, "管理员账号已更新", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/settings", status_code=303)

    @app.post("/settings/account/password", include_in_schema=False)
    async def settings_account_password_submit(
        request: Request,
        current_password: str = Form(...),
        new_password: str = Form(...),
        confirm_password: str = Form(...),
    ):
        admin = _require_admin(request)
        if admin is None:
            return RedirectResponse(url="/login", status_code=303)
        try:
            normalized_new_password = new_password or ""
            if normalized_new_password != (confirm_password or ""):
                raise ValueError("两次输入的新密码不一致")
            update_admin_password(
                admin.id,
                current_password=current_password,
                new_password=normalized_new_password,
            )
            _set_flash(request, "管理员密码已更新", "success")
        except Exception as exc:
            db.session.rollback()
            _set_flash(request, str(exc), "error")
        finally:
            db.remove()
        return RedirectResponse(url="/settings", status_code=303)


def _render(
    request: Request,
    template_name: str,
    *,
    title: str,
    admin: Any,
    status_code: int = 200,
    **context: Any,
) -> HTMLResponse:
    payload = {
        "app_name": Config.APP_NAME,
        "title": title,
        "admin": admin,
        "flash": _pop_flash(request),
        "current_timezone": settings_service.get_timezone_name(),
        "severity_labels": SEVERITY_LABELS,
        "status_labels": STATUS_LABELS,
        "enum_label": enum_label,
        **context,
    }
    return templates.TemplateResponse(request, template_name, payload, status_code=status_code)


def _get_current_admin(request: Request):
    admin_id = request.session.get(Config.ADMIN_SESSION_KEY)
    admin = get_admin_by_id(admin_id)
    if admin is None and admin_id is not None:
        request.session.pop(Config.ADMIN_SESSION_KEY, None)
    return admin


def _require_admin(request: Request):
    if not is_initialized():
        return None
    return _get_current_admin(request)


def _set_flash(request: Request, message: str, level: str) -> None:
    request.session["_flash"] = {"message": message, "level": level}


def _pop_flash(request: Request) -> dict[str, str] | None:
    return request.session.pop("_flash", None)


def _wants_json_response(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    requested_with = request.headers.get("x-requested-with", "")
    return "application/json" in accept or requested_with.lower() == "xmlhttprequest"


def _extract_push_rule_items(form: Any) -> list[dict[str, Any]]:
    rule_items = []
    for raw_item in form.getlist("rule_payload"):
        try:
            payload = json.loads(raw_item)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            rule_items.append(payload)

    if rule_items:
        return rule_items

    rule_types = form.getlist("rule_type")
    rule_sources = form.getlist("rule_source")
    rule_severities = form.getlist("rule_severity")
    rule_statuses = form.getlist("rule_status")
    rule_nvd_vuln_statuses = form.getlist("rule_nvd_vuln_status")
    rule_products = form.getlist("rule_affected_products")

    for index in range(
        max(
            len(rule_types),
            len(rule_sources),
            len(rule_severities),
            len(rule_statuses),
            len(rule_nvd_vuln_statuses),
            len(rule_products),
        )
    ):
        rule_type = rule_types[index] if index < len(rule_types) else RULE_TYPE_VULNERABILITY
        rule_items.append(
            {
                "rule_type": rule_type,
                "source": rule_sources[index] if index < len(rule_sources) else "all",
                "severity_levels": [rule_severities[index]] if index < len(rule_severities) and rule_severities[index] else [],
                "status": rule_statuses[index] if index < len(rule_statuses) else "all",
                "nvd_vuln_status": rule_nvd_vuln_statuses[index] if index < len(rule_nvd_vuln_statuses) else "all",
                "affected_products": rule_products[index] if index < len(rule_products) else "",
            }
        )

    return rule_items


def _build_pagination_pages(current_page: int, total_pages: int) -> list[int | str]:
    if total_pages <= 7:
        return list(range(1, total_pages + 1))

    pages = {1, total_pages}
    pages.update(range(max(1, current_page - 2), min(total_pages, current_page + 2) + 1))

    if current_page <= 4:
        pages.update(range(1, min(total_pages, 5) + 1))
    if current_page >= total_pages - 3:
        pages.update(range(max(1, total_pages - 4), total_pages + 1))

    output: list[int | str] = []
    previous = None
    for page_number in sorted(pages):
        if previous is not None and page_number - previous > 1:
            output.append("...")
        output.append(page_number)
        previous = page_number
    return output


def _build_push_rule_source_options(existing_sources: list[str]) -> list[str]:
    options = ["all", *list_supported_vulnerability_sources()]
    for item in existing_sources:
        normalized = str(item).strip().lower()
        if normalized.startswith("github") or normalized in {"阿里云漏洞库", "aliyun_avd", "manual"}:
            continue
        if item not in options:
            options.append(item)
    return options


def _build_nvd_vuln_status_options() -> list[str]:
    return [
        "all",
        "RECEIVED",
        "AWAITING ANALYSIS",
        "UNDERGOING ANALYSIS",
        "ANALYZED",
        "MODIFIED",
        "DEFERRED",
        "REJECTED",
    ]
