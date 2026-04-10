from __future__ import annotations

import logging
import math
import threading
from datetime import UTC, datetime
from urllib.parse import urlparse

import requests
from sqlalchemy import func, or_

from seceventmonitor.extensions import db
from seceventmonitor.models import GithubMonitoredTool
from seceventmonitor.services import settings as settings_service
from seceventmonitor.services.github_api_service import list_enabled_github_api_configs, mark_github_api_config_used
from seceventmonitor.services.http_client import build_session
from seceventmonitor.services.pushers.service import dispatch_github_tool_notifications


GITHUB_API_BASE = "https://api.github.com"
logger = logging.getLogger(__name__)
_REFRESH_EXECUTION_LOCK = threading.Lock()
_ASYNC_REFRESH_QUEUE_LOCK = threading.Lock()
_ASYNC_REFRESH_PENDING_IDS: set[int] = set()
_ASYNC_REFRESH_WORKER_ACTIVE = False


def list_github_monitored_tools_paginated(page=1, page_size=10, keyword=""):
    timezone_name = settings_service.get_timezone_name()
    page = max(int(page or 1), 1)
    page_size = min(max(int(page_size or 10), 1), 100)
    keyword = (keyword or "").strip().lower()

    query = GithubMonitoredTool.query
    if keyword:
        pattern = f"%{keyword}%"
        query = query.filter(
            or_(
                func.lower(GithubMonitoredTool.tool_name).like(pattern),
                func.lower(GithubMonitoredTool.repo_full_name).like(pattern),
                func.lower(GithubMonitoredTool.repo_url).like(pattern),
            )
        )

    query = query.order_by(GithubMonitoredTool.repo_updated_at.desc(), GithubMonitoredTool.id.desc())
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


def refresh_github_monitored_tools(tool_ids: list[int] | None = None, progress_callback=None):
    with _REFRESH_EXECUTION_LOCK:
        query = GithubMonitoredTool.query.order_by(GithubMonitoredTool.id.asc())
        if tool_ids:
            query = query.filter(GithubMonitoredTool.id.in_(tool_ids)).order_by(GithubMonitoredTool.id.asc())
        item_ids = [item.id for item in query.all() if item.id is not None]
        total = len(item_ids)
        if total == 0:
            return {
                "total": 0,
                "updated": 0,
                "failed": 0,
                "errors": [],
            }

        client = _GithubMetadataClient()
        updated = 0
        failed = 0
        errors: list[str] = []
        notification_targets: list[dict] = []

        for index, tool_id in enumerate(item_ids, start=1):
            item = db.session.get(GithubMonitoredTool, tool_id)
            if item is None:
                continue

            repo_full_name = (item.repo_full_name or f"id:{tool_id}").strip()
            tool_label = (item.tool_name or repo_full_name).strip()
            if progress_callback is not None:
                progress_callback(
                    current_index=index,
                    total_count=total,
                    tool_name=tool_label,
                )
            try:
                metadata = client.fetch_repo_metadata(repo_full_name)
                duplicate_item = _find_repo_full_name_duplicate(item.id, metadata["repo_full_name"])
                if duplicate_item is not None:
                    previous_state = _snapshot_tool_state(duplicate_item)
                    changed = _tool_metadata_changed(duplicate_item, metadata)
                    event_type = _resolve_github_tool_event_type(previous_state, metadata)
                    _apply_metadata(duplicate_item, metadata)
                    db.session.delete(item)
                    db.session.commit()
                    if changed:
                        updated += 1
                    if changed and event_type:
                        notification_targets.append(_build_github_tool_notification_target(duplicate_item, event_type, previous_state))
                    continue
                previous_state = _snapshot_tool_state(item)
                changed = _tool_metadata_changed(item, metadata)
                event_type = _resolve_github_tool_event_type(previous_state, metadata)
                _apply_metadata(item, metadata)
                db.session.commit()
                if changed:
                    updated += 1
                if changed and event_type:
                    notification_targets.append(_build_github_tool_notification_target(item, event_type, previous_state))
            except Exception as exc:
                db.session.rollback()
                failed += 1
                errors.append(f"{repo_full_name}: {exc}")

        return {
            "total": total,
            "updated": updated,
            "failed": failed,
            "errors": errors,
            "queued_notifications": len(notification_targets),
            "notification_targets": notification_targets,
        }


def import_github_monitored_tools(repo_links_text: str):
    normalized_entries, invalid_count = _parse_repo_lines(repo_links_text)
    if not normalized_entries:
        raise ValueError("请至少输入一个有效的 GitHub 仓库链接")

    created = 0
    updated = 0
    staged_items: list[GithubMonitoredTool] = []

    for entry in normalized_entries:
        item = _find_existing_tool_by_repo(entry["repo_full_name"], entry["repo_url"])
        if item is None:
            item = GithubMonitoredTool(repo_full_name=entry["repo_full_name"])
            db.session.add(item)
            created += 1
        else:
            updated += 1
        _stage_tool_for_refresh(item, entry)
        staged_items.append(item)

    db.session.flush()
    queued_ids = [item.id for item in staged_items if item.id is not None]
    db.session.commit()
    start_github_monitored_tools_refresh_async(queued_ids)
    return {
        "created": created,
        "updated": updated,
        "total": len(normalized_entries),
        "invalid_count": invalid_count,
        "queued": len(queued_ids),
    }


def update_github_monitored_tool(tool_id: int, repo_url: str):
    item = db.session.get(GithubMonitoredTool, tool_id)
    if item is None:
        raise ValueError("GitHub 监控仓库不存在")

    parsed = _parse_single_repo(repo_url)
    duplicate = _find_existing_tool_by_repo(
        parsed["repo_full_name"],
        parsed["repo_url"],
        exclude_tool_id=tool_id,
    )
    if duplicate is not None:
        raise ValueError("该 GitHub 仓库已存在于监控列表")

    _stage_tool_for_refresh(item, parsed, clear_metadata=item.repo_full_name != parsed["repo_full_name"])
    db.session.commit()
    start_github_monitored_tools_refresh_async([item.id])
    return item.to_dict(timezone_name=settings_service.get_timezone_name())


def delete_github_monitored_tool(tool_id: int):
    item = db.session.get(GithubMonitoredTool, tool_id)
    if item is None:
        raise ValueError("GitHub 监控仓库不存在")
    db.session.delete(item)
    db.session.commit()


def _apply_metadata(item: GithubMonitoredTool, metadata: dict):
    item.repo_full_name = metadata["repo_full_name"]
    item.repo_url = metadata["repo_url"]
    item.tool_name = metadata["tool_name"]
    item.version = metadata["version"]
    item.repo_updated_at = metadata["repo_updated_at"]
    item.last_synced_at = datetime.now(UTC).replace(tzinfo=None)


def _stage_tool_for_refresh(item: GithubMonitoredTool, parsed_entry: dict[str, str], *, clear_metadata: bool = False):
    repo_full_name = parsed_entry["repo_full_name"]
    repo_url = parsed_entry["repo_url"]
    placeholder_name = repo_full_name.split("/", 1)[-1]

    item.repo_full_name = repo_full_name
    item.repo_url = repo_url
    if clear_metadata or not (item.tool_name or "").strip():
        item.tool_name = placeholder_name
    if clear_metadata or not (item.version or "").strip():
        item.version = "-"
    if clear_metadata:
        item.repo_updated_at = None
        item.last_synced_at = None


def start_github_monitored_tools_refresh_async(tool_ids: list[int]):
    global _ASYNC_REFRESH_WORKER_ACTIVE
    normalized_ids = []
    seen = set()
    for tool_id in tool_ids or []:
        try:
            normalized_id = int(tool_id)
        except (TypeError, ValueError):
            continue
        if normalized_id <= 0 or normalized_id in seen:
            continue
        seen.add(normalized_id)
        normalized_ids.append(normalized_id)

    if not normalized_ids:
        return

    with _ASYNC_REFRESH_QUEUE_LOCK:
        _ASYNC_REFRESH_PENDING_IDS.update(normalized_ids)
        if _ASYNC_REFRESH_WORKER_ACTIVE:
            return
        _ASYNC_REFRESH_WORKER_ACTIVE = True

    worker = threading.Thread(
        target=_refresh_github_monitored_tools_worker_loop,
        name="github-tools-refresh-worker",
        daemon=True,
    )
    worker.start()


def _refresh_github_monitored_tools_worker_loop():
    global _ASYNC_REFRESH_WORKER_ACTIVE
    try:
        while True:
            with _ASYNC_REFRESH_QUEUE_LOCK:
                if not _ASYNC_REFRESH_PENDING_IDS:
                    _ASYNC_REFRESH_WORKER_ACTIVE = False
                    break
                tool_ids = sorted(_ASYNC_REFRESH_PENDING_IDS)
                _ASYNC_REFRESH_PENDING_IDS.clear()

            result = refresh_github_monitored_tools(tool_ids=tool_ids)
            if result.get("notification_targets"):
                dispatch_github_tool_notifications(result["notification_targets"])
            if result.get("failed"):
                logger.warning(
                    "async github tool refresh finished with failures: total=%s updated=%s failed=%s errors=%s",
                    result.get("total"),
                    result.get("updated"),
                    result.get("failed"),
                    result.get("errors"),
                )
    except Exception:
        logger.exception("async github tool refresh failed")
        with _ASYNC_REFRESH_QUEUE_LOCK:
            _ASYNC_REFRESH_WORKER_ACTIVE = False
    finally:
        db.remove()


def _tool_metadata_changed(item: GithubMonitoredTool, metadata: dict) -> bool:
    comparable_fields = [
        "repo_full_name",
        "repo_url",
        "tool_name",
        "version",
        "repo_updated_at",
    ]
    for field_name in comparable_fields:
        if getattr(item, field_name) != metadata.get(field_name):
            return True
    return False


def _snapshot_tool_state(item: GithubMonitoredTool) -> dict:
    return {
        "repo_full_name": item.repo_full_name,
        "repo_url": item.repo_url,
        "tool_name": item.tool_name,
        "version": item.version,
        "repo_updated_at": item.repo_updated_at,
        "last_synced_at": item.last_synced_at,
    }


def _resolve_github_tool_event_type(previous_state: dict, metadata: dict) -> str | None:
    changed_fields = {
        field_name
        for field_name in ["repo_full_name", "repo_url", "tool_name", "version", "repo_updated_at"]
        if previous_state.get(field_name) != metadata.get(field_name)
    }
    if not changed_fields:
        return None
    if previous_state.get("last_synced_at") is None:
        return "new_repo"

    previous_version = str(previous_state.get("version") or "").strip()
    current_version = str(metadata.get("version") or "").strip()
    if (
        "version" in changed_fields
        and previous_version
        and previous_version != "-"
        and current_version
        and current_version != "-"
        and previous_version != current_version
    ):
        return "version_updated"
    return "repo_updated"


def _build_github_tool_notification_target(item: GithubMonitoredTool, event_type: str, previous_state: dict) -> dict:
    return {
        "id": item.id,
        "github_tool_id": item.id,
        "event_type": event_type,
        "tool_name": item.tool_name,
        "repo_full_name": item.repo_full_name,
        "repo_url": item.repo_url,
        "version": item.version,
        "previous_version": previous_state.get("version"),
        "repo_updated_at": item.repo_updated_at,
        "previous_repo_updated_at": previous_state.get("repo_updated_at"),
    }


def _find_existing_tool_by_repo(repo_full_name: str, repo_url: str, exclude_tool_id: int | None = None):
    normalized_repo_full_name = _normalize_repo_identity(repo_full_name)
    normalized_repo_url = _normalize_repo_url(repo_url)
    if not normalized_repo_full_name:
        return None

    query = GithubMonitoredTool.query.filter(
        or_(
            func.lower(GithubMonitoredTool.repo_full_name) == normalized_repo_full_name,
            func.lower(GithubMonitoredTool.repo_url) == normalized_repo_url,
        )
    ).order_by(GithubMonitoredTool.id.asc())
    if exclude_tool_id is not None:
        query = query.filter(GithubMonitoredTool.id != exclude_tool_id)
    return query.first()


def _find_repo_full_name_duplicate(current_tool_id: int, repo_full_name: str):
    return _find_existing_tool_by_repo(
        repo_full_name,
        f"https://github.com/{(repo_full_name or '').strip()}",
        exclude_tool_id=current_tool_id,
    )


def _parse_repo_lines(repo_links_text: str) -> tuple[list[dict[str, str]], int]:
    seen: set[str] = set()
    items: list[dict[str, str]] = []
    invalid_lines: list[str] = []
    for raw_line in (repo_links_text or "").splitlines():
        raw_value = (raw_line or "").strip()
        if not raw_value:
            continue
        try:
            item = _parse_single_repo(raw_value)
        except ValueError:
            invalid_lines.append(raw_value)
            continue
        if item["repo_full_name"].lower() in seen:
            continue
        seen.add(item["repo_full_name"].lower())
        items.append(item)

    if invalid_lines and not items:
        raise ValueError("输入的 GitHub 仓库链接无效")
    return items, len(invalid_lines)


def _parse_single_repo(value: str) -> dict[str, str]:
    text = (value or "").strip()
    if not text:
        raise ValueError("GitHub 仓库链接不能为空")

    if "://" not in text and "github.com" not in text and text.count("/") == 1:
        owner, repo = [item.strip() for item in text.split("/", 1)]
    else:
        normalized = text
        if "://" not in normalized:
            normalized = f"https://{normalized}"
        parsed = urlparse(normalized)
        hostname = (parsed.netloc or "").lower()
        if hostname not in {"github.com", "www.github.com"}:
            raise ValueError("仅支持 GitHub 仓库链接")
        path_parts = [item for item in parsed.path.split("/") if item]
        if len(path_parts) < 2:
            raise ValueError("GitHub 仓库链接格式不正确")
        owner, repo = path_parts[0].strip(), path_parts[1].strip()

    repo = repo.removesuffix(".git").strip()
    if not owner or not repo:
        raise ValueError("GitHub 仓库链接格式不正确")
    repo_full_name = f"{owner}/{repo}"
    return {
        "repo_full_name": repo_full_name,
        "repo_url": f"https://github.com/{repo_full_name}",
    }


def _normalize_repo_identity(value: str) -> str:
    return (value or "").strip().strip("/").removesuffix(".git").lower()


def _normalize_repo_url(value: str) -> str:
    normalized = (value or "").strip()
    if not normalized:
        return ""
    if "://" not in normalized:
        normalized = f"https://{normalized}"
    parsed = urlparse(normalized)
    hostname = (parsed.netloc or "").lower()
    path = (parsed.path or "").strip().rstrip("/").removesuffix(".git")
    return f"{parsed.scheme.lower()}://{hostname}{path}".lower()


class _GithubMetadataClient:
    def __init__(self):
        self.proxy_url = settings_service.get_settings_map().get("http_proxy", "")
        self.token_configs = [
            item
            for item in list_enabled_github_api_configs()
            if (item.api_token or "").strip()
        ]

    def fetch_repo_metadata(self, repo_full_name: str) -> dict:
        repo_payload = self._request_json(f"/repos/{repo_full_name}")
        version, repo_updated_at = self._fetch_repo_version(repo_full_name)

        return {
            "repo_full_name": repo_payload.get("full_name") or repo_full_name,
            "repo_url": repo_payload.get("html_url") or f"https://github.com/{repo_full_name}",
            "tool_name": repo_payload.get("name") or repo_full_name.split("/", 1)[-1],
            "version": version,
            "repo_updated_at": repo_updated_at,
        }

    def _fetch_repo_version(self, repo_full_name: str) -> tuple[str, datetime | None]:
        latest_release = self._request_json(f"/repos/{repo_full_name}/releases/latest", allow_404=True)
        if latest_release:
            version = (latest_release.get("tag_name") or latest_release.get("name") or "").strip()
            if version:
                published_at = _parse_datetime(
                    latest_release.get("published_at") or latest_release.get("created_at")
                )
                return version, published_at

        latest_tags = self._request_json(f"/repos/{repo_full_name}/tags", params={"per_page": 1}, allow_404=True)
        if latest_tags and isinstance(latest_tags, list):
            first_tag = latest_tags[0] or {}
            version = (first_tag.get("name") or "").strip()
            if version:
                commit_sha = str(((first_tag.get("commit") or {}).get("sha") or "")).strip()
                published_at = self._fetch_tag_commit_datetime(repo_full_name, commit_sha)
                return version, published_at

        return "-", None

    def _fetch_tag_commit_datetime(self, repo_full_name: str, commit_sha: str) -> datetime | None:
        if not commit_sha:
            return None
        commit_payload = self._request_json(f"/repos/{repo_full_name}/commits/{commit_sha}", allow_404=True)
        if not commit_payload:
            return None
        commit_info = commit_payload.get("commit") or {}
        committer = commit_info.get("committer") or {}
        author = commit_info.get("author") or {}
        return _parse_datetime(committer.get("date") or author.get("date"))

    def _request_json(self, path: str, params: dict | None = None, allow_404: bool = False):
        last_error: Exception | None = None

        for token_config in [*self.token_configs, None]:
            response = None
            session = None
            try:
                session = build_session(
                    proxy_url=self.proxy_url,
                    headers=_build_github_headers(token_config.api_token if token_config is not None else ""),
                )
                response = session.get(f"{GITHUB_API_BASE}{path}", params=params, timeout=20)
                if token_config is not None:
                    mark_github_api_config_used(token_config)
                if allow_404 and response.status_code == 404:
                    return None
                if response.status_code == 404:
                    raise ValueError("GitHub 仓库不存在或无权访问")
                if response.ok:
                    return response.json()
                if token_config is not None and response.status_code in {401, 403}:
                    last_error = ValueError("GitHub API Token 无效或已限流")
                    continue
                response.raise_for_status()
            except requests.RequestException as exc:
                last_error = exc
                if token_config is not None:
                    continue
                break
            finally:
                if response is not None:
                    response.close()
                try:
                    session.close()
                except Exception:
                    pass

        if last_error is None:
            raise ValueError("GitHub API 请求失败")
        if isinstance(last_error, ValueError):
            raise last_error
        raise ValueError(f"GitHub API 请求失败: {last_error}") from last_error


def _build_github_headers(api_token: str) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
    }
    token = (api_token or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _parse_datetime(value: str | None):
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC).replace(tzinfo=None)
    return parsed.astimezone(UTC).replace(tzinfo=None)
