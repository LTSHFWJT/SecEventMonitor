from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin


BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/135.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

_MULTISPACE_PATTERN = re.compile(r"[ \t\r\f\v]+")
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
_RANGE_PATTERNS = [
    re.compile(r"^(?P<start>[A-Za-z0-9_.:+~-]+)\s*<=\s*(?P<product>.+?)\s*<=\s*(?P<end>[A-Za-z0-9_.:+~-]+)$"),
    re.compile(r"^(?P<start>[A-Za-z0-9_.:+~-]+)\s*<=\s*(?P<product>.+?)\s*<\s*(?P<end>[A-Za-z0-9_.:+~-]+)$"),
    re.compile(r"^(?P<start>[A-Za-z0-9_.:+~-]+)\s*<\s*(?P<product>.+?)\s*<=\s*(?P<end>[A-Za-z0-9_.:+~-]+)$"),
    re.compile(r"^(?P<start>[A-Za-z0-9_.:+~-]+)\s*<\s*(?P<product>.+?)\s*<\s*(?P<end>[A-Za-z0-9_.:+~-]+)$"),
    re.compile(r"^(?P<product>.+?)\s*<=\s*(?P<end>[A-Za-z0-9_.:+~-]+)$"),
    re.compile(r"^(?P<product>.+?)\s*<\s*(?P<end>[A-Za-z0-9_.:+~-]+)$"),
    re.compile(r"^(?P<product>.+?)\s*>=\s*(?P<start>[A-Za-z0-9_.:+~-]+)$"),
    re.compile(r"^(?P<product>.+?)\s*>\s*(?P<start>[A-Za-z0-9_.:+~-]+)$"),
    re.compile(r"^(?P<product>.+?)\s*=\s*(?P<exact>[A-Za-z0-9_.:+~-]+)$"),
]
_TITLE_SPLIT_PATTERN = re.compile(r"[（(【\[]")


def resolve_since(since, fallback_days=7):
    if since is not None:
        if since.tzinfo is None:
            return since.replace(tzinfo=UTC)
        return since.astimezone(UTC)
    return datetime.now(UTC) - timedelta(days=fallback_days)


def clean_text(value: str | None) -> str:
    lines = []
    for raw_line in str(value or "").replace("\xa0", " ").splitlines():
        line = _MULTISPACE_PATTERN.sub(" ", raw_line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


def clean_inline_text(value: str | None) -> str:
    return _MULTISPACE_PATTERN.sub(" ", str(value or "").replace("\xa0", " ")).strip()


def extract_cve_id(*values: str | None) -> str:
    for value in values:
        match = _CVE_PATTERN.search(str(value or ""))
        if match:
            return match.group(0).upper()
    return ""


def normalize_severity(value: str | None) -> str:
    text = clean_inline_text(value).lower()
    mapping = {
        "critical": "critical",
        "严重": "critical",
        "极危": "critical",
        "严重漏洞": "critical",
        "high": "high",
        "高危": "high",
        "高": "high",
        "高风险": "high",
        "medium": "medium",
        "中危": "medium",
        "中": "medium",
        "中风险": "medium",
        "low": "low",
        "低危": "low",
        "低": "low",
        "低风险": "low",
        "info": "unknown",
        "informational": "unknown",
        "未知": "unknown",
        "n/a": "unknown",
    }
    return mapping.get(text, "unknown")


def parse_datetime_value(value) -> datetime | None:
    if value in (None, ""):
        return None

    if isinstance(value, datetime):
        parsed = value
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 1_000_000_000_000:
            timestamp /= 1000
        return datetime.fromtimestamp(timestamp, tz=UTC)

    text = clean_inline_text(str(value))
    if not text:
        return None

    normalized = (
        text.replace("/", "-")
        .replace(".", "-")
        .replace("年", "-")
        .replace("月", "-")
        .replace("日", "")
        .replace("T", " ")
        .replace("Z", "+00:00")
    )
    normalized = re.sub(r"\s+", " ", normalized).strip()

    for fmt in (
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ):
        try:
            parsed = datetime.strptime(normalized, fmt)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        except ValueError:
            continue

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def normalize_url(base_url: str, value: str | None) -> str:
    href = clean_inline_text(value)
    if not href:
        return ""
    return urljoin(base_url, href)


def collect_unique_lines(*blocks: str | None) -> list[str]:
    output = []
    seen = set()
    for block in blocks:
        for raw_line in str(block or "").splitlines():
            line = clean_inline_text(raw_line.lstrip("•").lstrip("-"))
            lowered = line.lower()
            if not line or lowered in seen:
                continue
            seen.add(lowered)
            output.append(line)
    return output


def guess_affected_products(title: str | None = "", fallback: str | None = "") -> str:
    candidates = []
    for value in (title, fallback):
        text = clean_inline_text(value)
        if not text:
            continue
        text = _TITLE_SPLIT_PATTERN.split(text, 1)[0]
        text = re.sub(r"\bCVE-\d{4}-\d+\b", "", text, flags=re.IGNORECASE)
        text = re.split(r"漏洞|安全通告|漏洞通告|风险通告|安全公告", text, maxsplit=1)[0]
        text = clean_inline_text(text)
        if text:
            candidates.append(text)
    unique = []
    seen = set()
    for item in candidates:
        lowered = item.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        unique.append(item)
    return "\n".join(unique)


def build_entry_from_simple_range(line: str, default_product: str = "") -> dict | None:
    text = clean_inline_text(line)
    if not text:
        return None

    text = text.replace("（", "(").replace("）", ")")
    for pattern in _RANGE_PATTERNS:
        match = pattern.match(text)
        if not match:
            continue
        product = clean_inline_text(match.groupdict().get("product") or default_product)
        if not product:
            return None
        group_dict = match.groupdict()
        start_value = clean_inline_text(group_dict.get("start")) or None
        end_value = clean_inline_text(group_dict.get("end")) or None
        exact_value = clean_inline_text(group_dict.get("exact")) or None
        version_start_including = None
        version_start_excluding = None
        version_end_including = None
        version_end_excluding = None
        if exact_value:
            pass
        elif start_value and end_value:
            if text.find("<=") == text.find(start_value) + len(start_value):
                version_start_including = start_value
            else:
                version_start_excluding = start_value
            if text.rsplit(end_value, 1)[0].rstrip().endswith("<="):
                version_end_including = end_value
            else:
                version_end_excluding = end_value
        elif start_value:
            if ">=" in text:
                version_start_including = start_value
            else:
                version_start_excluding = start_value
        elif end_value:
            if "<=" in text:
                version_end_including = end_value
            else:
                version_end_excluding = end_value
        return {
            "part": "a",
            "part_label": "应用",
            "vendor": "",
            "product": product,
            "product_label": product,
            "display_label": f"[应用] {product}",
            "version_exact": exact_value,
            "version_start_including": version_start_including,
            "version_start_excluding": version_start_excluding,
            "version_end_including": version_end_including,
            "version_end_excluding": version_end_excluding,
            "criteria": "",
        }

    return build_product_only_entry(text or default_product)


def build_product_only_entry(product: str | None) -> dict | None:
    normalized = clean_inline_text(product)
    if not normalized:
        return None
    return {
        "part": "a",
        "part_label": "应用",
        "vendor": "",
        "product": normalized,
        "product_label": normalized,
        "display_label": f"[应用] {normalized}",
        "version_exact": None,
        "version_start_including": None,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": None,
        "criteria": "",
    }
