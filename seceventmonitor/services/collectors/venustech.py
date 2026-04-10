from __future__ import annotations

import re
import time
from pathlib import Path

from lxml import html

from seceventmonitor.models import Vulnerability
from seceventmonitor.services.collectors.base import BaseCollector
from seceventmonitor.services.collectors.helpers import (
    BROWSER_HEADERS,
    build_product_only_entry,
    build_entry_from_simple_range,
    clean_inline_text,
    clean_text,
    collect_unique_lines,
    extract_cve_id,
    guess_affected_products,
    normalize_severity,
    normalize_url,
    parse_datetime_value,
    resolve_since,
)
from seceventmonitor.utils.affected_versions import (
    build_affected_products_text,
    build_affected_versions_text,
    serialize_affected_entries,
)


class VenustechCollector(BaseCollector):
    source_name = "启明星辰漏洞通告"
    list_url = "https://www.venustech.com.cn/new_type/aqtg/"
    max_pages = 20
    request_interval_seconds = 0.0

    def __init__(self, settings=None, session=None):
        super().__init__(settings=settings, session=session)
        self._last_request_monotonic = None

    def default_headers(self):
        return BROWSER_HEADERS

    def fetch(self, since=None, limit=None, progress_callback=None):
        since = resolve_since(since, fallback_days=30)
        records = []
        seen_urls = set()

        page_index = 1
        while self.max_pages <= 0 or page_index <= self.max_pages:
            links = self.fetch_list_page(page_index, seen_urls=seen_urls)
            if not links:
                break

            page_new_count = 0
            should_stop = False
            existing_keys = self._load_existing_vulnerability_keys(links)
            for detail_url in links:
                if self._build_vuln_key(detail_url) in existing_keys:
                    should_stop = True
                    break
                record = self._fetch_detail(detail_url)
                compare_time = record.get("last_seen_at") or record.get("published_at")
                if compare_time is not None and compare_time < since:
                    continue
                page_new_count += 1
                records.append(record)
                if limit is not None and len(records) >= limit:
                    return records

            if progress_callback:
                progress_callback(page_index=page_index, page_size=len(links), fetched_count=len(records), total_results=None)
            if should_stop or page_new_count == 0:
                break
            page_index += 1

        return records

    def fetch_list_page(self, page_index: int, *, seen_urls: set[str] | None = None) -> list[str]:
        page_url = self.list_url if page_index == 1 else f"{self.list_url}index_{page_index}.html"
        self._sleep_before_request()
        response = self.session.get(page_url, timeout=self.timeout)
        self._last_request_monotonic = time.monotonic()
        response.raise_for_status()
        document = html.fromstring(response.content)

        output = []
        for href in document.xpath("//div[contains(@class, 'main-inner-bt')]//li/a[contains(@href, '.html')]/@href"):
            url = normalize_url(self.list_url, href)
            if not url:
                continue
            if seen_urls is not None:
                if url in seen_urls:
                    continue
                seen_urls.add(url)
            output.append(url)
        return output

    def _load_existing_vulnerability_keys(self, detail_urls: list[str]) -> set[str]:
        vuln_keys = [self._build_vuln_key(detail_url) for detail_url in detail_urls if self._build_vuln_key(detail_url)]
        if not vuln_keys:
            return set()
        items = Vulnerability.query.filter(Vulnerability.vuln_key.in_(vuln_keys)).all()
        return {item.vuln_key for item in items}

    @staticmethod
    def _build_vuln_key(detail_url: str) -> str:
        stem = Path(detail_url).stem
        return f"venustech:{stem}" if stem else ""

    def _fetch_detail(self, detail_url: str):
        self._sleep_before_request()
        response = self.session.get(detail_url, timeout=self.timeout)
        self._last_request_monotonic = time.monotonic()
        response.raise_for_status()
        document = html.fromstring(response.content)
        container = document.xpath("//div[contains(@class, 'news-content')]")
        content_root = container[0] if container else document

        title = clean_inline_text(
            "".join(content_root.xpath("./h3[contains(@class, 'news-title')][1]//text()"))
        ).removeprefix("【漏洞通告】")
        published_at = parse_datetime_value(
            clean_inline_text("".join(content_root.xpath(".//span[contains(@class, 'news-time')][1]//text()")))
        )

        body_root = content_root.xpath(".//div[contains(@class, 'news_text')]")
        body_root = body_root[0] if body_root else content_root
        fields, sections, section_labels = self._extract_structured_content(body_root)

        description_lines = sections.get("漏洞概述", [])
        affected_lines = sections.get("影响范围", [])
        if not description_lines and sections.get("漏洞详情"):
            description_lines, legacy_affected_lines = self._split_old_detail_lines(sections.get("漏洞详情", []))
            if not affected_lines:
                affected_lines = legacy_affected_lines

        reference_lines = collect_unique_lines(
            *sections.get(("安全措施", "参考链接"), []),
            *sections.get("参考链接", []),
        )
        remediation_lines = self._build_remediation_lines(sections, section_labels)
        serialized_sections = self._serialize_sections(sections)

        affected_entries = self._build_affected_entries(affected_lines, title)
        description = "\n".join(collect_unique_lines(*description_lines))

        return {
            "vuln_key": f"venustech:{Path(detail_url).stem}",
            "cve_id": extract_cve_id(fields.get("CVE ID"), title, description),
            "title": title,
            "description": description,
            "description_lang": "zh",
            "severity": normalize_severity(fields.get("漏洞等级") or fields.get("等级")),
            "base_score": self._to_float(fields.get("漏洞评分")),
            "attack_vector": fields.get("攻击向量") or self._infer_attack_vector(fields.get("远程利用")),
            "attack_complexity": fields.get("攻击复杂度") or fields.get("利用难度"),
            "privileges_required": fields.get("所需权限"),
            "user_interaction": fields.get("用户交互"),
            "affected_versions": build_affected_versions_text(affected_entries) or "\n".join(affected_lines) or None,
            "affected_products": build_affected_products_text(affected_entries) or guess_affected_products(title, description),
            "affected_version_data": serialize_affected_entries(affected_entries) if affected_entries else None,
            "exploit_maturity": fields.get("PoC/EXP"),
            "remediation": "\n".join(remediation_lines),
            "source_payload": {
                "fields": fields,
                "references": reference_lines,
                "sections": serialized_sections,
            },
            "source": self.source_name,
            "reference_url": detail_url,
            "published_at": parse_datetime_value(fields.get("发现时间")) or published_at,
            "last_seen_at": published_at or parse_datetime_value(fields.get("发现时间")),
            "payload": {
                "references": reference_lines,
                "fields": fields,
                "sections": serialized_sections,
            },
        }

    def _extract_structured_content(self, body_root):
        fields = {}
        sections: dict[object, list[str]] = {}
        section_labels: dict[object, str] = {}
        current_h2 = None
        current_h3 = None

        for child in body_root.iterchildren():
            if not isinstance(child.tag, str):
                continue
            tag_name = child.tag.lower()
            raw_text = clean_text("".join(child.xpath(".//text()")))
            normalized_text = self._normalize_heading(raw_text)

            if tag_name == "h2":
                if not normalized_text:
                    continue
                current_h2 = normalized_text
                current_h3 = None
                section_labels[current_h2] = clean_inline_text(raw_text)
                continue

            if current_h2 is None:
                if tag_name == "h3" and normalized_text in {"漏洞概述", "漏洞详情", "安全建议", "参考链接", "版本信息", "附录"}:
                    current_h2 = normalized_text
                    current_h3 = None
                    section_labels[current_h2] = clean_inline_text(raw_text)
                continue

            if tag_name == "h3":
                if not normalized_text:
                    continue
                if current_h2 in {"安全措施", "附录"}:
                    current_h3 = normalized_text
                    section_labels[(current_h2, current_h3)] = clean_inline_text(raw_text)
                elif normalized_text in {"漏洞概述", "漏洞详情", "安全建议", "参考链接", "版本信息", "附录"}:
                    current_h2 = normalized_text
                    current_h3 = None
                    section_labels[current_h2] = clean_inline_text(raw_text)
                else:
                    current_h3 = normalized_text
                    section_labels[(current_h2, current_h3)] = clean_inline_text(raw_text)
                continue

            if tag_name == "table":
                if current_h2 == "漏洞概述" and not fields:
                    fields.update(self._extract_fields_from_table(child))
                continue

            if not raw_text:
                continue
            key = (current_h2, current_h3) if current_h3 else current_h2
            sections.setdefault(key, []).append(raw_text)

        return fields, sections, section_labels

    def _extract_fields_from_table(self, table_node):
        fields = {}
        for row in table_node.xpath(".//tr"):
            cells = [
                clean_inline_text(" ".join(text for text in cell.xpath(".//text()") if clean_inline_text(text)))
                for cell in row.xpath("./td")
            ]
            if len(cells) < 2:
                continue
            for index in range(0, len(cells) - 1, 2):
                key = self._normalize_field_key(cells[index])
                value = clean_inline_text(cells[index + 1]).replace(" 、", "、")
                if key:
                    fields[key] = value
        return fields

    def _build_remediation_lines(self, sections: dict, section_labels: dict[object, str]):
        blocks = []
        for subsection_key in ("升级版本", "临时措施", "通用建议"):
            lines = sections.get(("安全措施", subsection_key), [])
            if not lines:
                continue
            title = section_labels.get(("安全措施", subsection_key), subsection_key)
            block = [title]
            block.extend(self._normalize_block_lines(collect_unique_lines(*lines)))
            blocks.append("\n".join(block))
        if blocks:
            return collect_unique_lines(*blocks)

        legacy_lines = sections.get("安全建议", [])
        if legacy_lines:
            return self._normalize_block_lines(collect_unique_lines(*legacy_lines))
        return collect_unique_lines(*blocks)

    @staticmethod
    def _normalize_heading(value: str | None) -> str:
        text = re.sub(r"\s+", "", clean_inline_text(value))
        mapping = {
            "一、漏洞概述": "漏洞概述",
            "二、影响范围": "影响范围",
            "三、安全措施": "安全措施",
            "四、版本信息": "版本信息",
            "五、附录": "附录",
            "0x00漏洞概述": "漏洞概述",
            "0x01漏洞详情": "漏洞详情",
            "0x02安全建议": "安全建议",
            "0x03参考链接": "参考链接",
            "0x04版本信息": "版本信息",
            "0x05附录": "附录",
            "3.1升级版本": "升级版本",
            "3.2临时措施": "临时措施",
            "3.3通用建议": "通用建议",
            "3.4参考链接": "参考链接",
            "5.1公司简介": "公司简介",
            "5.2关于我们": "关于我们",
        }
        return mapping.get(text, text)

    @staticmethod
    def _normalize_field_key(value: str | None) -> str:
        text = re.sub(r"\s+", "", clean_inline_text(value))
        mapping = {
            "CVEID": "CVE ID",
            "时间": "发现时间",
            "发现时间": "发现时间",
            "类型": "漏洞类型",
            "漏洞类型": "漏洞类型",
            "等级": "漏洞等级",
            "漏洞等级": "漏洞等级",
            "攻击向量": "攻击向量",
            "所需权限": "所需权限",
            "利用难度": "攻击复杂度",
            "攻击复杂度": "攻击复杂度",
            "用户交互": "用户交互",
            "PoC/EXP": "PoC/EXP",
            "在野利用": "在野利用",
            "漏洞评分": "漏洞评分",
            "远程利用": "远程利用",
            "影响范围": "影响范围",
            "漏洞名称": "漏洞名称",
        }
        return mapping.get(text, clean_inline_text(value))

    @staticmethod
    def _normalize_block_lines(lines: list[str]) -> list[str]:
        output = []
        for line in lines:
            normalized = clean_inline_text(line)
            normalized = re.sub(r"^[lI](?=[0-9\u4e00-\u9fff])", "", normalized)
            normalized = re.sub(r"^[lI1]\s+", "", normalized)
            if normalized:
                output.append(normalized)
        return output

    @staticmethod
    def _split_old_detail_lines(lines: list[str]):
        normalized_lines = [clean_inline_text(item) for item in lines if clean_inline_text(item)]
        if not normalized_lines:
            return [], []

        for index, line in enumerate(normalized_lines):
            if line == "影响范围":
                return normalized_lines[:index], normalized_lines[index + 1 :]
        return normalized_lines, []

    def _build_affected_entries(self, affected_lines: list[str], title: str):
        entries = []
        guessed_products = guess_affected_products(title)
        default_product = guessed_products.splitlines()[0] if guessed_products else ""
        for line in affected_lines:
            normalized_line = clean_inline_text(line).lstrip("·•")
            version_split = re.split(r"版本[：:]", normalized_line, maxsplit=1)
            if len(version_split) == 2:
                product_part = clean_inline_text(version_split[0]).removesuffix("版本")
                version_part = clean_inline_text(version_split[1])
                entry = build_entry_from_simple_range(
                    f"{product_part} {version_part}",
                    default_product=product_part or default_product,
                )
                if entry is None and product_part:
                    entry = build_product_only_entry(product_part)
            else:
                candidate_line = re.sub(r"(?P<product>.+?)版本\s*(?P<op>[<>=].+)$", r"\g<product> \g<op>", normalized_line)
                entry = build_entry_from_simple_range(candidate_line, default_product=default_product)
            if entry:
                entries.append(entry)
        return entries

    @staticmethod
    def _serialize_sections(sections: dict[object, list[str]]) -> dict[str, list[str]]:
        serialized = {}
        for key, value in sections.items():
            if isinstance(key, tuple):
                normalized_key = " / ".join(str(item) for item in key if item)
            else:
                normalized_key = str(key)
            serialized[normalized_key] = value
        return serialized

    @staticmethod
    def _to_float(value):
        text = clean_inline_text(value)
        if not text or text.lower() in {"n/a", "na", "none", "null", "暂无", "未知", "-"}:
            return None
        match = re.search(r"-?\d+(?:\.\d+)?", text)
        if not match:
            return None
        try:
            return float(match.group(0))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _infer_attack_vector(value: str | None) -> str | None:
        text = clean_inline_text(value)
        if text == "是":
            return "网络"
        return None

    def _sleep_before_request(self):
        if self._last_request_monotonic is None:
            return
        elapsed = time.monotonic() - self._last_request_monotonic
        remaining = self.request_interval_seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)
