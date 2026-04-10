import math
from datetime import UTC, datetime

from seceventmonitor.extensions import db
from seceventmonitor.models import TranslationApiConfig
from seceventmonitor.services import settings as settings_service


def list_translation_api_configs_paginated(page=1, page_size=10):
    timezone_name = settings_service.get_timezone_name()
    page = max(int(page or 1), 1)
    page_size = min(max(int(page_size or 10), 1), 100)

    query = TranslationApiConfig.query.order_by(TranslationApiConfig.created_at.desc(), TranslationApiConfig.id.desc())
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


def list_enabled_translation_api_configs():
    items = TranslationApiConfig.query.filter_by(enabled=True).all()
    return sorted(
        items,
        key=lambda item: (
            item.last_used_at is not None,
            item.last_used_at or datetime.min.replace(tzinfo=None),
            item.id,
        ),
    )


def create_translation_api_config(*, app_id: str, api_key: str, enabled: bool = True):
    normalized_app_id = (app_id or "").strip()
    normalized_api_key = (api_key or "").strip()

    if not normalized_app_id:
        raise ValueError("APPID 不能为空")
    if not normalized_api_key:
        raise ValueError("API-KEY 不能为空")
    if TranslationApiConfig.query.filter_by(app_id=normalized_app_id).first() is not None:
        raise ValueError("APPID 已存在")

    config = TranslationApiConfig(
        app_id=normalized_app_id,
        api_key=normalized_api_key,
        enabled=bool(enabled),
    )
    db.session.add(config)
    db.session.commit()
    return config.to_dict(timezone_name=settings_service.get_timezone_name())


def update_translation_api_config(config_id: int, *, app_id: str, api_key: str = "", enabled: bool = True):
    config = db.session.get(TranslationApiConfig, config_id)
    if config is None:
        raise ValueError("翻译 API 配置不存在")

    normalized_app_id = (app_id or "").strip()
    normalized_api_key = (api_key or "").strip()
    if not normalized_app_id:
        raise ValueError("APPID 不能为空")

    duplicate = TranslationApiConfig.query.filter(
        TranslationApiConfig.app_id == normalized_app_id,
        TranslationApiConfig.id != config_id,
    ).first()
    if duplicate is not None:
        raise ValueError("APPID 已存在")

    config.app_id = normalized_app_id
    if normalized_api_key:
        config.api_key = normalized_api_key
    config.enabled = bool(enabled)
    db.session.commit()
    return config.to_dict(timezone_name=settings_service.get_timezone_name())


def toggle_translation_api_config(config_id: int):
    config = db.session.get(TranslationApiConfig, config_id)
    if config is None:
        raise ValueError("翻译 API 配置不存在")
    config.enabled = not config.enabled
    db.session.commit()
    return config.to_dict(timezone_name=settings_service.get_timezone_name())


def delete_translation_api_config(config_id: int):
    config = db.session.get(TranslationApiConfig, config_id)
    if config is None:
        raise ValueError("翻译 API 配置不存在")
    db.session.delete(config)
    db.session.commit()


def mark_translation_api_config_used(config):
    config.last_used_at = datetime.now(UTC).replace(tzinfo=None)
    db.session.flush()


def get_translation_api_config(config_id: int):
    return db.session.get(TranslationApiConfig, config_id)
