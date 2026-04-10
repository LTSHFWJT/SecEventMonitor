import logging
import math
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from seceventmonitor.extensions import db
from seceventmonitor.models import GithubApiConfig
from seceventmonitor.services import settings as settings_service

logger = logging.getLogger(__name__)


def list_github_api_configs_paginated(page=1, page_size=10):
    timezone_name = settings_service.get_timezone_name()
    page = max(int(page or 1), 1)
    page_size = min(max(int(page_size or 10), 1), 100)

    query = GithubApiConfig.query.order_by(GithubApiConfig.created_at.desc(), GithubApiConfig.id.desc())
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


def list_enabled_github_api_configs():
    items = GithubApiConfig.query.filter_by(enabled=True).all()
    return sorted(
        items,
        key=lambda item: (
            item.last_used_at is not None,
            item.last_used_at or datetime.min.replace(tzinfo=None),
            item.id,
        ),
    )


def create_github_api_config(*, name: str, api_token: str, enabled: bool = True):
    normalized_name = (name or "").strip()
    normalized_api_token = (api_token or "").strip()

    if not normalized_name:
        raise ValueError("名称不能为空")
    if not normalized_api_token:
        raise ValueError("API Token 不能为空")
    if GithubApiConfig.query.filter_by(name=normalized_name).first() is not None:
        raise ValueError("名称已存在")

    config = GithubApiConfig(
        name=normalized_name,
        api_token=normalized_api_token,
        enabled=bool(enabled),
    )
    db.session.add(config)
    db.session.commit()
    return config.to_dict(timezone_name=settings_service.get_timezone_name())


def update_github_api_config(config_id: int, *, name: str, api_token: str = "", enabled: bool = True):
    config = db.session.get(GithubApiConfig, config_id)
    if config is None:
        raise ValueError("GitHub API 配置不存在")

    normalized_name = (name or "").strip()
    normalized_api_token = (api_token or "").strip()
    if not normalized_name:
        raise ValueError("名称不能为空")

    duplicate = GithubApiConfig.query.filter(
        GithubApiConfig.name == normalized_name,
        GithubApiConfig.id != config_id,
    ).first()
    if duplicate is not None:
        raise ValueError("名称已存在")

    config.name = normalized_name
    if normalized_api_token:
        config.api_token = normalized_api_token
    config.enabled = bool(enabled)
    db.session.commit()
    return config.to_dict(timezone_name=settings_service.get_timezone_name())


def toggle_github_api_config(config_id: int):
    config = db.session.get(GithubApiConfig, config_id)
    if config is None:
        raise ValueError("GitHub API 配置不存在")
    config.enabled = not config.enabled
    db.session.commit()
    return config.to_dict(timezone_name=settings_service.get_timezone_name())


def delete_github_api_config(config_id: int):
    config = db.session.get(GithubApiConfig, config_id)
    if config is None:
        raise ValueError("GitHub API 配置不存在")
    db.session.delete(config)
    db.session.commit()


def mark_github_api_config_used(config):
    config_id = getattr(config, "id", None)
    if not config_id:
        return False

    last_used_at = datetime.now(UTC).replace(tzinfo=None)
    try:
        with db.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE github_api_configs
                    SET last_used_at = :last_used_at,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = :config_id
                    """
                ),
                {
                    "last_used_at": last_used_at,
                    "config_id": config_id,
                },
            )
        try:
            config.last_used_at = last_used_at
        except Exception:
            pass
        return True
    except OperationalError as exc:
        logger.debug("skip github api last_used_at update due to database lock: config_id=%s error=%s", config_id, exc)
        return False


def get_github_api_config(config_id: int):
    return db.session.get(GithubApiConfig, config_id)
