#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from lxml import etree

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.models import Vulnerability
from seceventmonitor.services.collectors.helpers import (
    clean_inline_text,
    clean_text,
    extract_cve_id,
    guess_affected_products,
    normalize_severity,
    parse_datetime_value,
)
from seceventmonitor.services.sync_service import upsert_vulnerabilities


CNNVD_SOURCE_NAME = "CNNVD"
CNNVD_REFERENCE_URL = "https://www.cnnvd.org.cn/"
XML_FILE_GLOB = "*.xml"
SEVERITY_TO_BASE = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import all CNNVD XML history files from selfproject into the current database.",
    )
    parser.add_argument(
        "--xml-dir",
        default="selfproject",
        help="Directory containing CNNVD XML files. Default: selfproject",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=200,
        help="Number of parsed XML entries to process per batch. Default: 200",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional limit on imported non-duplicate records for debugging.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and count import candidates without writing to the database.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    create_app()

    xml_dir = Path(args.xml_dir).expanduser()
    if not xml_dir.is_absolute():
        xml_dir = ROOT_DIR / xml_dir
    if not xml_dir.exists():
        raise SystemExit(f"XML directory not found: {xml_dir}")

    batch_size = max(int(args.batch_size or 0), 1)
    import_limit = max(int(args.limit or 0), 0)
    xml_files = sorted(path for path in xml_dir.rglob(XML_FILE_GLOB) if path.is_file())
    if not xml_files:
        raise SystemExit(f"No XML files found under: {xml_dir}")

    before_total = Vulnerability.query.count()
    before_source_total = Vulnerability.query.filter_by(source=CNNVD_SOURCE_NAME).count()
    started_at = time.monotonic()

    print(
        f"[start] xml_dir={xml_dir} files={len(xml_files)} batch_size={batch_size} "
        f"limit={import_limit or 'all'} dry_run={args.dry_run} "
        f"total_before={before_total} source_before={before_source_total}",
        flush=True,
    )

    parsed_entries = 0
    parser_recover_errors = 0
    skipped_existing = 0
    skipped_duplicate = 0
    inserted = 0
    updated = 0
    pending: list[dict] = []
    seen_vuln_keys: set[str] = set()

    try:
        for file_index, xml_path in enumerate(xml_files, start=1):
            file_records, file_error_count = _parse_xml_file(xml_path)
            parser_recover_errors += file_error_count
            print(
                f"[file] {file_index}/{len(xml_files)} path={xml_path.relative_to(ROOT_DIR)} "
                f"entries={len(file_records)} recover_errors={file_error_count}",
                flush=True,
            )

            for record in file_records:
                parsed_entries += 1
                vuln_key = record["vuln_key"]
                if vuln_key in seen_vuln_keys:
                    skipped_duplicate += 1
                    continue
                seen_vuln_keys.add(vuln_key)
                pending.append(record)

                if import_limit and (inserted + len(pending)) >= import_limit:
                    pending = pending[: max(import_limit - inserted, 0)]
                    break

                if len(pending) >= batch_size:
                    batch_result = _flush_batch(pending, dry_run=args.dry_run)
                    skipped_existing += batch_result["skipped_existing"]
                    inserted += batch_result["inserted"]
                    updated += batch_result["updated"]
                    pending = []
                    print(
                        f"[commit] parsed={parsed_entries} inserted={inserted} updated={updated} "
                        f"skipped_existing={skipped_existing} skipped_duplicate={skipped_duplicate}",
                        flush=True,
                    )

            if import_limit and inserted >= import_limit:
                break

        if pending:
            batch_result = _flush_batch(pending, dry_run=args.dry_run)
            skipped_existing += batch_result["skipped_existing"]
            inserted += batch_result["inserted"]
            updated += batch_result["updated"]
            print(
                f"[commit] parsed={parsed_entries} inserted={inserted} updated={updated} "
                f"skipped_existing={skipped_existing} skipped_duplicate={skipped_duplicate}",
                flush=True,
            )

        if args.dry_run:
            db.session.rollback()

        after_total = Vulnerability.query.count()
        after_source_total = Vulnerability.query.filter_by(source=CNNVD_SOURCE_NAME).count()
        elapsed = time.monotonic() - started_at
        print(
            f"[done] parsed={parsed_entries} inserted={inserted} updated={updated} "
            f"skipped_existing={skipped_existing} skipped_duplicate={skipped_duplicate} "
            f"recover_errors={parser_recover_errors} total_before={before_total} total_after={after_total} "
            f"source_before={before_source_total} source_after={after_source_total} "
            f"elapsed_seconds={elapsed:.1f}",
            flush=True,
        )
        return 0
    finally:
        db.remove()


def _parse_xml_file(xml_path: Path) -> tuple[list[dict], int]:
    parser = etree.XMLParser(recover=True, huge_tree=True)
    tree = etree.parse(str(xml_path), parser)
    entries = []
    for entry_node in tree.getroot().findall(".//entry"):
        normalized = _normalize_entry(entry_node, xml_path)
        if normalized is not None:
            entries.append(normalized)
    return entries, len(parser.error_log)


def _normalize_entry(entry_node, xml_path: Path) -> dict | None:
    title = _text(entry_node.find("name"))
    cnnvd_code = _text(entry_node.find("vuln-id")).upper()
    if not title or not cnnvd_code:
        return None

    description = _text(entry_node.find("vuln-descript")) or title
    severity_label = _text(entry_node.find("severity"))
    severity = normalize_severity(severity_label)
    cve_id = extract_cve_id(
        _text(entry_node.find("other-id/cve-id")),
        title,
        description,
    )
    remediation = _text(entry_node.find("vuln-solution"))
    published_at = parse_datetime_value(_text(entry_node.find("published")))
    last_seen_at = parse_datetime_value(_text(entry_node.find("modified"))) or published_at
    source_value = _text(entry_node.find("source"))

    source_payload = {
        "xml_file": str(xml_path.relative_to(ROOT_DIR)),
        "name": title,
        "vuln_id": cnnvd_code,
        "published": _text(entry_node.find("published")),
        "modified": _text(entry_node.find("modified")),
        "source": source_value,
        "severity": severity_label,
        "vuln_type": _text(entry_node.find("vuln-type")),
        "vuln_descript": description,
        "cve_id": _text(entry_node.find("other-id/cve-id")),
        "bugtraq_id": _text(entry_node.find("other-id/bugtraq-id")),
        "vuln_solution": remediation,
    }

    return {
        "vuln_key": f"cnnvd:{cnnvd_code}",
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "description_lang": "zh",
        "severity": severity,
        "base_severity": SEVERITY_TO_BASE.get(severity),
        "affected_versions": None,
        "affected_products": guess_affected_products(title, description) or None,
        "affected_version_data": None,
        "remediation": remediation or "",
        "source_payload": source_payload,
        "source": CNNVD_SOURCE_NAME,
        "reference_url": source_value or CNNVD_REFERENCE_URL,
        "published_at": published_at,
        "last_seen_at": last_seen_at,
        "payload": {
            "xml_file": source_payload["xml_file"],
            "vuln_id": cnnvd_code,
            "cve_id": cve_id,
        },
    }


def _flush_batch(records: list[dict], *, dry_run: bool) -> dict[str, int]:
    if not records:
        return {
            "inserted": 0,
            "updated": 0,
            "skipped_existing": 0,
        }

    vuln_keys = [item["vuln_key"] for item in records]
    existing_vuln_keys = {
        row[0]
        for row in db.session.query(Vulnerability.vuln_key)
        .filter(Vulnerability.vuln_key.in_(vuln_keys))
        .all()
    }
    new_records = [item for item in records if item["vuln_key"] not in existing_vuln_keys]
    skipped_existing = len(records) - len(new_records)
    if not new_records:
        return {
            "inserted": 0,
            "updated": 0,
            "skipped_existing": skipped_existing,
        }

    if dry_run:
        return {
            "inserted": len(new_records),
            "updated": 0,
            "skipped_existing": skipped_existing,
        }

    inserted, updated, _ = upsert_vulnerabilities(new_records)
    db.session.commit()
    return {
        "inserted": inserted,
        "updated": updated,
        "skipped_existing": skipped_existing,
    }


def _text(node) -> str:
    if node is None:
        return ""
    return clean_text("".join(node.itertext())) or clean_inline_text(node.text)


if __name__ == "__main__":
    raise SystemExit(main())
