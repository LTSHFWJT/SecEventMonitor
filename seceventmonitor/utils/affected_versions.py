from __future__ import annotations

import json
import re


PART_LABELS = {
    "a": "应用",
    "o": "操作系统",
    "h": "硬件",
}

_TOKEN_PATTERN = re.compile(r"\d+|[a-zA-Z]+")
_DISPLAY_LINE_PATTERN = re.compile(r"^(?:\[(?P<part_label>[^\]]+)\]\s*)?(?P<label>.*?):\s*(?P<version_text>.+)$")


def build_affected_entry_from_cpe_match(match: dict) -> dict | None:
    if not match.get("vulnerable"):
        return None

    cpe_data = _parse_cpe_criteria(match.get("criteria") or "")
    product_label = cpe_data["product_label"]
    if not product_label:
        return None

    version_exact = _normalize_version_value(cpe_data["version"])
    if _has_range_fields(match):
        version_exact = None

    return {
        "part": cpe_data["part"],
        "part_label": cpe_data["part_label"],
        "vendor": cpe_data["vendor"],
        "product": cpe_data["product"],
        "product_label": product_label,
        "display_label": _build_display_label(cpe_data["part_label"], product_label),
        "version_exact": version_exact,
        "version_start_including": _normalize_version_value(match.get("versionStartIncluding")),
        "version_start_excluding": _normalize_version_value(match.get("versionStartExcluding")),
        "version_end_including": _normalize_version_value(match.get("versionEndIncluding")),
        "version_end_excluding": _normalize_version_value(match.get("versionEndExcluding")),
        "criteria": match.get("criteria") or "",
    }


def build_affected_versions_text(entries: list[dict]) -> str:
    lines = []
    seen = set()
    for entry in entries:
        line = format_affected_entry(entry)
        if not line or line in seen:
            continue
        seen.add(line)
        lines.append(line)
    return "\n".join(lines)


def build_affected_products_text(entries: list[dict]) -> str:
    products = []
    seen = set()
    for entry in entries:
        for value in [
            entry.get("display_label"),
            entry.get("product_label"),
            entry.get("vendor"),
            entry.get("product"),
        ]:
            normalized = (value or "").strip()
            lowered = normalized.lower()
            if not normalized or lowered in seen:
                continue
            seen.add(lowered)
            products.append(normalized)
    return "\n".join(products)


def serialize_affected_entries(entries: list[dict]) -> str:
    return json.dumps(entries or [], ensure_ascii=False, separators=(",", ":"))


def deserialize_affected_entries(raw: str | None, fallback_text: str = "") -> list[dict]:
    raw = (raw or "").strip()
    if raw:
        try:
            payload = json.loads(raw)
            if isinstance(payload, list):
                return [item for item in payload if isinstance(item, dict)]
        except json.JSONDecodeError:
            pass
    return parse_affected_versions_text(fallback_text)


def parse_affected_versions_text(text: str | None) -> list[dict]:
    output = []
    for line in (text or "").splitlines():
        item = _parse_display_line(line.strip())
        if item:
            output.append(item)
    return output


def matches_affected_filters(
    entries: list[dict],
    *,
    product_keyword: str = "",
    version_keyword: str = "",
) -> bool:
    product_keyword = (product_keyword or "").strip().lower()
    version_keyword = (version_keyword or "").strip()

    if not product_keyword and not version_keyword:
        return True
    if not entries:
        return False

    for entry in entries:
        if product_keyword and not _matches_product(entry, product_keyword):
            continue
        if version_keyword and not _matches_version(entry, version_keyword):
            continue
        return True
    return False


def format_affected_entry(entry: dict) -> str:
    display_label = (entry.get("display_label") or "").strip()
    if not display_label:
        display_label = _build_display_label(entry.get("part_label"), entry.get("product_label"))
    if not display_label:
        return ""

    range_parts = []
    if entry.get("version_start_including"):
        range_parts.append(f">= {entry['version_start_including']}")
    if entry.get("version_start_excluding"):
        range_parts.append(f"> {entry['version_start_excluding']}")
    if entry.get("version_end_including"):
        range_parts.append(f"<= {entry['version_end_including']}")
    if entry.get("version_end_excluding"):
        range_parts.append(f"< {entry['version_end_excluding']}")

    if range_parts:
        version_text = ", ".join(range_parts)
    elif entry.get("version_exact"):
        version_text = entry["version_exact"]
    else:
        version_text = "所有受影响版本"

    return f"{display_label}: {version_text}"


def _parse_cpe_criteria(criteria: str) -> dict:
    if not criteria.startswith("cpe:2.3:"):
        return {
            "part": "",
            "part_label": "",
            "vendor": "",
            "product": "",
            "product_label": "",
            "version": "",
        }

    parts = criteria.split(":")
    if len(parts) < 6:
        return {
            "part": "",
            "part_label": "",
            "vendor": "",
            "product": "",
            "product_label": "",
            "version": "",
        }

    part = parts[2]
    vendor = parts[3].replace("\\", "")
    product = parts[4].replace("\\", "")
    version = parts[5].replace("\\", "")
    if vendor and product and vendor != product:
        product_label = f"{vendor}/{product}"
    else:
        product_label = product or vendor

    return {
        "part": part,
        "part_label": PART_LABELS.get(part, ""),
        "vendor": vendor,
        "product": product,
        "product_label": product_label,
        "version": version,
    }


def _build_display_label(part_label: str | None, product_label: str | None) -> str:
    part_label = (part_label or "").strip()
    product_label = (product_label or "").strip()
    if part_label and product_label:
        return f"[{part_label}] {product_label}"
    return product_label


def _has_range_fields(match: dict) -> bool:
    return any(
        match.get(key)
        for key in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    )


def _normalize_version_value(value: str | None) -> str | None:
    value = (value or "").strip()
    if value in ("", "*", "-"):
        return None
    return value


def _parse_display_line(line: str) -> dict | None:
    if not line:
        return None

    matched = _DISPLAY_LINE_PATTERN.match(line)
    if not matched:
        return None

    part_label = (matched.group("part_label") or "").strip()
    product_label = (matched.group("label") or "").strip()
    version_text = (matched.group("version_text") or "").strip()
    entry = {
        "part": "",
        "part_label": part_label,
        "vendor": "",
        "product": "",
        "product_label": product_label,
        "display_label": _build_display_label(part_label, product_label),
        "version_exact": None,
        "version_start_including": None,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": None,
        "criteria": "",
    }

    if version_text == "所有受影响版本":
        return entry

    for item in [segment.strip() for segment in version_text.split(",") if segment.strip()]:
        if item.startswith(">="):
            entry["version_start_including"] = item[2:].strip()
        elif item.startswith(">"):
            entry["version_start_excluding"] = item[1:].strip()
        elif item.startswith("<="):
            entry["version_end_including"] = item[2:].strip()
        elif item.startswith("<"):
            entry["version_end_excluding"] = item[1:].strip()
        else:
            entry["version_exact"] = item

    return entry


def _matches_product(entry: dict, product_keyword: str) -> bool:
    values = [
        entry.get("display_label"),
        entry.get("product_label"),
        entry.get("vendor"),
        entry.get("product"),
        entry.get("criteria"),
    ]
    return any(product_keyword in (value or "").lower() for value in values if value)


def _matches_version(entry: dict, version_keyword: str) -> bool:
    version_keyword = version_keyword.strip()
    if not version_keyword:
        return True

    exact = (entry.get("version_exact") or "").strip()
    start_including = (entry.get("version_start_including") or "").strip()
    start_excluding = (entry.get("version_start_excluding") or "").strip()
    end_including = (entry.get("version_end_including") or "").strip()
    end_excluding = (entry.get("version_end_excluding") or "").strip()

    if not any([exact, start_including, start_excluding, end_including, end_excluding]):
        return True

    if exact:
        return _compare_versions(version_keyword, exact) == 0

    if start_including and _compare_versions(version_keyword, start_including) < 0:
        return False
    if start_excluding and _compare_versions(version_keyword, start_excluding) <= 0:
        return False
    if end_including and _compare_versions(version_keyword, end_including) > 0:
        return False
    if end_excluding and _compare_versions(version_keyword, end_excluding) >= 0:
        return False
    return True


def _compare_versions(left: str, right: str) -> int:
    left_tokens = _tokenize_version(left)
    right_tokens = _tokenize_version(right)
    max_len = max(len(left_tokens), len(right_tokens))

    for index in range(max_len):
        left_token = left_tokens[index] if index < len(left_tokens) else None
        right_token = right_tokens[index] if index < len(right_tokens) else None
        if left_token == right_token:
            continue
        if left_token is None:
            return _compare_missing_to_token(right_token)
        if right_token is None:
            return -_compare_missing_to_token(left_token)
        if isinstance(left_token, int) and isinstance(right_token, int):
            return -1 if left_token < right_token else 1
        if isinstance(left_token, str) and isinstance(right_token, str):
            return -1 if left_token < right_token else 1
        if isinstance(left_token, int):
            return 1
        return -1

    return 0


def _compare_missing_to_token(token: int | str | None) -> int:
    if token is None:
        return 0
    if isinstance(token, int):
        return 0 if token == 0 else -1
    return 1


def _tokenize_version(value: str) -> list[int | str]:
    return [int(item) if item.isdigit() else item.lower() for item in _TOKEN_PATTERN.findall((value or "").strip())]
