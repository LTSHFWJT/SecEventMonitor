from __future__ import annotations

import json
import logging
import math
import re
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import requests
from sqlalchemy import func, or_

from seceventmonitor.extensions import db
from seceventmonitor.models import GithubPocEntry
from seceventmonitor.services import settings as settings_service
from seceventmonitor.services.github_api_service import list_enabled_github_api_configs, mark_github_api_config_used
from seceventmonitor.services.http_client import build_session


GITHUB_API_BASE = "https://api.github.com"
POC_REPOSITORY_FULL_NAME = "nomi-sec/PoC-in-GitHub"
POC_ARCHIVE_URL_TEMPLATE = "https://github.com/{repo_full_name}/archive/refs/heads/{branch}.zip"
POC_FILE_PATTERN = re.compile(r"^(?P<year>\d{4})/(?P<cve_id>CVE-\d{4}-\d+)\.json$", re.IGNORECASE)
logger = logging.getLogger(__name__)


def list_github_poc_entries_paginated(page=1, page_size=10, keyword="", status="all"):
    timezone_name = settings_service.get_timezone_name()
    page = max(int(page or 1), 1)
    page_size = min(max(int(page_size or 10), 1), 100)
    keyword = (keyword or "").strip().lower()
    status = (status or "all").strip().lower()

    query = GithubPocEntry.query
    if keyword:
        pattern = f"%{keyword}%"
        query = query.filter(
            or_(
                func.lower(GithubPocEntry.cve_id).like(pattern),
                func.lower(GithubPocEntry.repo_full_name).like(pattern),
                func.lower(func.coalesce(GithubPocEntry.description, "")).like(pattern),
                func.lower(func.coalesce(GithubPocEntry.owner_login, "")).like(pattern),
            )
        )
    if status != "all":
        query = query.filter(func.lower(GithubPocEntry.status) == status)

    query = query.order_by(
        GithubPocEntry.repo_updated_at.desc(),
        GithubPocEntry.repo_pushed_at.desc(),
        GithubPocEntry.id.desc(),
    )
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


def sync_github_poc_entries(progress_callback=None):
    client = _GithubPocRepositoryClient()
    repo_metadata = client.fetch_repository_metadata()
    default_branch = repo_metadata["default_branch"]
    tree_entries = client.fetch_repository_tree(default_branch)
    poc_files = [
        {"path": entry["path"], "sha": entry["sha"], "cve_id": _extract_cve_id_from_path(entry["path"])}
        for entry in tree_entries
        if _extract_cve_id_from_path(entry["path"])
    ]
    poc_files.sort(key=lambda item: item["path"])

    total_files = len(poc_files)
    current_paths = {item["path"] for item in poc_files}
    existing_sha_map = _load_existing_source_file_sha_map()
    changed_files = [item for item in poc_files if existing_sha_map.get(item["path"]) != item["sha"]]
    removed_files = sorted(set(existing_sha_map.keys()) - current_paths)

    deleted = 0
    if removed_files:
        deleted = _delete_removed_source_files(removed_files)

    if not changed_files:
        if deleted:
            db.session.commit()
        return {
            "total_files": total_files,
            "changed_files": 0,
            "inserted": 0,
            "updated": 0,
            "deleted": deleted,
            "queued_notifications": 0,
            "notification_targets": [],
        }

    archive_path = client.download_repository_archive(default_branch)
    inserted = 0
    updated = 0
    notification_targets: list[dict] = []

    try:
        with zipfile.ZipFile(archive_path) as archive:
            zip_index = _build_archive_index(archive)
            for index, file_entry in enumerate(changed_files, start=1):
                cve_id = file_entry["cve_id"]
                if progress_callback is not None:
                    progress_callback(
                        current_index=index,
                        total_count=len(changed_files),
                        tool_name=cve_id,
                    )
                members = _load_poc_members_from_archive(archive, zip_index, file_entry["path"])
                file_inserted, file_updated, file_deleted, file_notifications = _upsert_poc_file(
                    file_path=file_entry["path"],
                    file_sha=file_entry["sha"],
                    cve_id=cve_id,
                    members=members,
                )
                inserted += file_inserted
                updated += file_updated
                deleted += file_deleted
                notification_targets.extend(file_notifications)
                db.session.commit()
    finally:
        try:
            Path(archive_path).unlink(missing_ok=True)
        except Exception:
            logger.debug("failed to delete temporary github poc archive: %s", archive_path)

    return {
        "total_files": total_files,
        "changed_files": len(changed_files),
        "inserted": inserted,
        "updated": updated,
        "deleted": deleted,
        "queued_notifications": len(notification_targets),
        "notification_targets": notification_targets,
    }


def _load_existing_source_file_sha_map() -> dict[str, str]:
    rows = (
        db.session.query(GithubPocEntry.source_file_path, func.max(GithubPocEntry.source_file_sha))
        .filter(func.trim(func.coalesce(GithubPocEntry.source_file_path, "")) != "")
        .group_by(GithubPocEntry.source_file_path)
        .all()
    )
    return {str(path): str(sha or "") for path, sha in rows if path}


def _delete_removed_source_files(removed_files: list[str]) -> int:
    deleted = 0
    for file_path in removed_files:
        rows = GithubPocEntry.query.filter_by(source_file_path=file_path).all()
        for row in rows:
            db.session.delete(row)
            deleted += 1
    return deleted


def _build_archive_index(archive: zipfile.ZipFile) -> dict[str, str]:
    index: dict[str, str] = {}
    for member_name in archive.namelist():
        normalized_name = member_name.rstrip("/")
        if not normalized_name or "/" not in normalized_name:
            continue
        _, relative_name = normalized_name.split("/", 1)
        index[relative_name] = member_name
    return index


def _load_poc_members_from_archive(
    archive: zipfile.ZipFile,
    archive_index: dict[str, str],
    relative_path: str,
) -> list[dict]:
    member_name = archive_index.get(relative_path)
    if not member_name:
        raise FileNotFoundError(f"missing poc file in archive: {relative_path}")

    with archive.open(member_name) as handle:
        payload = json.loads(handle.read().decode("utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"unexpected poc payload type for {relative_path}")
    return [item for item in payload if isinstance(item, dict)]


def _upsert_poc_file(*, file_path: str, file_sha: str, cve_id: str, members: list[dict]):
    inserted = 0
    updated = 0
    deleted = 0
    notification_targets: list[dict] = []

    existing_rows = GithubPocEntry.query.filter_by(source_file_path=file_path).all()
    existing_by_repo_id = {row.repo_id: row for row in existing_rows}
    current_repo_ids: set[int] = set()

    for member in members:
        normalized = _normalize_poc_member(member, cve_id=cve_id, file_path=file_path, file_sha=file_sha)
        if normalized is None:
            continue
        repo_id = normalized["repo_id"]
        current_repo_ids.add(repo_id)
        row = existing_by_repo_id.get(repo_id)
        if row is None:
            row = GithubPocEntry.query.filter_by(repo_id=repo_id).first()
        if row is None:
            row = GithubPocEntry(poc_key=normalized["poc_key"], repo_id=repo_id)
            db.session.add(row)
            _apply_poc_data(row, normalized)
            row.status = "new"
            inserted += 1
            db.session.flush()
            notification_targets.append(_build_github_poc_notification_target(row, event_type="poc_new"))
            continue

        changed = _github_poc_changed(row, normalized)
        _apply_poc_data(row, normalized)
        if changed:
            row.status = "updated"
            updated += 1
            notification_targets.append(_build_github_poc_notification_target(row, event_type="poc_updated"))

    for row in existing_rows:
        if row.repo_id in current_repo_ids:
            continue
        db.session.delete(row)
        deleted += 1

    return inserted, updated, deleted, notification_targets


def _normalize_poc_member(member: dict, *, cve_id: str, file_path: str, file_sha: str):
    repo_id = member.get("id")
    try:
        normalized_repo_id = int(repo_id)
    except (TypeError, ValueError):
        return None

    owner = member.get("owner") or {}
    topics = [str(item).strip() for item in member.get("topics") or [] if str(item).strip()]
    return {
        "poc_key": f"github-poc:{normalized_repo_id}",
        "cve_id": cve_id,
        "repo_id": normalized_repo_id,
        "repo_name": (member.get("name") or "").strip(),
        "repo_full_name": (member.get("full_name") or "").strip(),
        "repo_url": (member.get("html_url") or "").strip(),
        "description": (member.get("description") or "").strip(),
        "owner_login": (owner.get("login") or "").strip(),
        "owner_id": owner.get("id"),
        "owner_url": (owner.get("html_url") or "").strip(),
        "repo_created_at": _parse_datetime(member.get("created_at")),
        "repo_updated_at": _parse_datetime(member.get("updated_at")),
        "repo_pushed_at": _parse_datetime(member.get("pushed_at")),
        "stargazers_count": _normalize_int(member.get("stargazers_count")),
        "watchers_count": _normalize_int(member.get("watchers_count")),
        "forks_count": _normalize_int(member.get("forks_count") or member.get("forks")),
        "subscribers_count": _normalize_int(member.get("subscribers_count")),
        "topics": topics,
        "source_file_path": file_path,
        "source_file_sha": file_sha,
        "source_payload": member,
        "last_synced_at": datetime.now(UTC).replace(tzinfo=None),
    }


def _apply_poc_data(row: GithubPocEntry, normalized: dict) -> None:
    row.poc_key = normalized["poc_key"]
    row.cve_id = normalized["cve_id"]
    row.repo_id = normalized["repo_id"]
    row.repo_name = normalized["repo_name"]
    row.repo_full_name = normalized["repo_full_name"]
    row.repo_url = normalized["repo_url"]
    row.description = normalized["description"]
    row.owner_login = normalized["owner_login"]
    row.owner_id = normalized["owner_id"]
    row.owner_url = normalized["owner_url"]
    row.repo_created_at = normalized["repo_created_at"]
    row.repo_updated_at = normalized["repo_updated_at"]
    row.repo_pushed_at = normalized["repo_pushed_at"]
    row.stargazers_count = normalized["stargazers_count"]
    row.watchers_count = normalized["watchers_count"]
    row.forks_count = normalized["forks_count"]
    row.subscribers_count = normalized["subscribers_count"]
    row.topics = normalized["topics"]
    row.source_file_path = normalized["source_file_path"]
    row.source_file_sha = normalized["source_file_sha"]
    row.source_payload = normalized["source_payload"]
    row.last_synced_at = normalized["last_synced_at"]


def _github_poc_changed(row: GithubPocEntry, normalized: dict) -> bool:
    comparable_fields = [
        "cve_id",
        "repo_name",
        "repo_full_name",
        "repo_url",
        "description",
        "owner_login",
        "owner_id",
        "owner_url",
        "repo_created_at",
        "repo_updated_at",
        "repo_pushed_at",
        "stargazers_count",
        "watchers_count",
        "forks_count",
        "subscribers_count",
        "topics",
        "source_file_path",
    ]
    for field_name in comparable_fields:
        if getattr(row, field_name) != normalized.get(field_name):
            return True
    return False


def _build_github_poc_notification_target(row: GithubPocEntry, *, event_type: str) -> dict:
    return {
        "id": row.id,
        "github_poc_id": row.id,
        "event_type": event_type,
        "cve_id": row.cve_id,
        "repo_name": row.repo_name,
        "repo_full_name": row.repo_full_name,
        "repo_url": row.repo_url,
        "description": row.description,
        "owner_login": row.owner_login,
        "repo_updated_at": row.repo_updated_at,
        "repo_pushed_at": row.repo_pushed_at,
        "stargazers_count": row.stargazers_count,
        "forks_count": row.forks_count,
    }


def _extract_cve_id_from_path(path: str) -> str:
    matched = POC_FILE_PATTERN.fullmatch(str(path or "").strip())
    if not matched:
        return ""
    return str(matched.group("cve_id") or "").upper()


def _parse_datetime(value: str | None):
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC).replace(tzinfo=None)
    return parsed.astimezone(UTC).replace(tzinfo=None)


def _normalize_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


class _GithubPocRepositoryClient:
    def __init__(self):
        self.proxy_url = settings_service.get_settings_map().get("http_proxy", "")
        self.token_configs = [
            item
            for item in list_enabled_github_api_configs()
            if (item.api_token or "").strip()
        ]

    def fetch_repository_metadata(self) -> dict:
        payload = self._request_json(f"/repos/{POC_REPOSITORY_FULL_NAME}")
        return {
            "default_branch": (payload.get("default_branch") or "master").strip() or "master",
        }

    def fetch_repository_tree(self, branch: str) -> list[dict]:
        payload = self._request_json(f"/repos/{POC_REPOSITORY_FULL_NAME}/git/trees/{branch}", params={"recursive": 1})
        if payload.get("truncated"):
            raise RuntimeError("GitHub 仓库树返回被截断，无法安全增量同步")
        return [
            {
                "path": str(item.get("path") or "").strip(),
                "sha": str(item.get("sha") or "").strip(),
            }
            for item in payload.get("tree") or []
            if (item.get("type") or "") == "blob"
        ]

    def download_repository_archive(self, branch: str) -> str:
        session = build_session(proxy_url=self.proxy_url)
        archive_file = tempfile.NamedTemporaryFile(prefix="github-poc-", suffix=".zip", delete=False)
        archive_path = archive_file.name
        archive_file.close()

        try:
            with session.get(
                POC_ARCHIVE_URL_TEMPLATE.format(repo_full_name=POC_REPOSITORY_FULL_NAME, branch=branch),
                timeout=120,
                stream=True,
            ) as response:
                response.raise_for_status()
                with open(archive_path, "wb") as handle:
                    for chunk in response.iter_content(chunk_size=1024 * 256):
                        if chunk:
                            handle.write(chunk)
            return archive_path
        except Exception:
            Path(archive_path).unlink(missing_ok=True)
            raise
        finally:
            session.close()

    def _request_json(self, path: str, params: dict | None = None):
        last_error: Exception | None = None

        for token_config in [*self.token_configs, None]:
            response = None
            session = None
            try:
                session = build_session(
                    proxy_url=self.proxy_url,
                    headers=_build_github_headers(token_config.api_token if token_config is not None else ""),
                )
                response = session.get(f"{GITHUB_API_BASE}{path}", params=params, timeout=30)
                if token_config is not None:
                    mark_github_api_config_used(token_config)
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
