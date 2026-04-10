import hashlib
import logging
import time

from seceventmonitor.services.http_client import build_session
from seceventmonitor.services.settings import get_settings_map
from seceventmonitor.services.translation_api_service import (
    list_enabled_translation_api_configs,
    mark_translation_api_config_used,
)


logger = logging.getLogger(__name__)

TRANSLATE_API_URL = "https://api.niutrans.com/v2/text/translate"


def translate_text_to_zh(text: str, source_language: str | None) -> str | None:
    normalized_text = (text or "").strip()
    normalized_source = normalize_translation_language(source_language)

    if not normalized_text:
        return ""
    if not normalized_source:
        return None
    if normalized_source == "zh":
        return normalized_text

    configs = list_enabled_translation_api_configs()
    if not configs:
        return None

    proxy_url = (get_settings_map().get("http_proxy") or "").strip()
    errors: list[str] = []
    for config in configs:
        try:
            translated = _translate_with_config(
                app_id=config.app_id,
                api_key=config.api_key,
                text=normalized_text,
                source_language=normalized_source,
                proxy_url=proxy_url,
            )
            mark_translation_api_config_used(config)
            return translated
        except Exception as exc:
            mark_translation_api_config_used(config)
            errors.append(f"{config.app_id}: {exc}")

    logger.warning("failed to translate text with all configured credentials: %s", " | ".join(errors))
    return None


def infer_translation_language(text: str, fallback_language: str | None = None) -> str | None:
    normalized_text = (text or "").strip()
    if not normalized_text:
        return None

    if _contains_cjk(normalized_text):
        return "zh"
    if _contains_latin(normalized_text):
        return "en"
    return normalize_translation_language(fallback_language)


def normalize_translation_language(value: str | None) -> str | None:
    text = (value or "").strip().lower()
    if not text:
        return None
    text = text.replace("_", "-")
    if text.startswith("zh"):
        return "zh"
    if "-" in text:
        text = text.split("-", 1)[0]
    return text or None


def _translate_with_config(*, app_id: str, api_key: str, text: str, source_language: str, proxy_url: str = "") -> str:
    timestamp = str(int(time.time()))
    request_data = {
        "from": source_language,
        "to": "zh",
        "srcText": text,
        "appId": (app_id or "").strip(),
        "timestamp": timestamp,
    }
    request_data["authStr"] = _generate_auth_str(request_data, (api_key or "").strip())

    session = build_session(proxy_url=proxy_url)
    try:
        response = session.post(
            TRANSLATE_API_URL,
            data=request_data,
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
    finally:
        session.close()

    error_code = payload.get("errorCode", payload.get("error_code"))
    if error_code not in (None, "", 0, "0"):
        raise RuntimeError(payload.get("errorMsg", payload.get("error_msg")) or str(error_code))

    translated = (payload.get("tgtText") or "").strip()
    if not translated:
        raise RuntimeError("翻译接口未返回译文")
    return translated


def _generate_auth_str(request_data: dict[str, str], api_key: str) -> str:
    items = [(key, value) for key, value in request_data.items() if value not in (None, "")]
    items.append(("apikey", api_key))
    items.sort(key=lambda item: item[0])
    param_str = "&".join(f"{key}={value}" for key, value in items)
    return hashlib.md5(param_str.encode("utf-8")).hexdigest()


def _contains_cjk(text: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in text)


def _contains_latin(text: str) -> bool:
    return any(("a" <= char.lower() <= "z") for char in text)
