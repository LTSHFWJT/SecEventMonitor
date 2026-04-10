#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.models import Vulnerability
from seceventmonitor.services.collectors.seebug import SeebugCollector
from seceventmonitor.services.collectors.helpers import parse_datetime_value
from seceventmonitor.services.collectors.threatbook import ThreatBookCollector
from seceventmonitor.services.collectors.venustech import VenustechCollector
from seceventmonitor.services.sync_service import upsert_vulnerabilities


SUPPORTED_SOURCES = ("threatbook", "seebug", "venustech")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Backfill ThreatBook, Seebug, and Venustech vulnerability history page-by-page and overwrite existing rows.",
    )
    parser.add_argument(
        "--sources",
        default=",".join(SUPPORTED_SOURCES),
        help=f"Comma-separated source keys. Supported: {', '.join(SUPPORTED_SOURCES)}",
    )
    parser.add_argument("--max-pages", type=int, default=0, help="Optional page cap per source for debugging.")
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=0.0,
        help="Delay between HTTP requests for each collector.",
    )
    parser.add_argument(
        "--threatbook-page-size",
        type=int,
        default=10,
        help="Per-page size for ThreatBook notice API.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    selected_sources = parse_sources(args.sources)
    create_app()

    failures = []
    try:
        for source_name in selected_sources:
            try:
                if source_name == "threatbook":
                    run_threatbook(args)
                elif source_name == "seebug":
                    run_seebug(args)
                elif source_name == "venustech":
                    run_venustech(args)
            except Exception as exc:  # noqa: BLE001
                failures.append((source_name, exc))
                db.session.rollback()
                db.remove()
                print(f"[error] source={source_name} error={exc}", flush=True)
    finally:
        db.remove()

    if failures:
        return 1
    return 0


def parse_sources(value: str) -> list[str]:
    output = []
    for raw in str(value or "").split(","):
        item = raw.strip().lower()
        if not item:
            continue
        if item not in SUPPORTED_SOURCES:
            raise SystemExit(f"unsupported source: {item}")
        if item not in output:
            output.append(item)
    if not output:
        raise SystemExit("no source selected")
    return output


def run_threatbook(args: argparse.Namespace) -> None:
    collector = ThreatBookCollector()
    collector.request_interval_seconds = max(float(args.sleep_seconds or 0), 0.0)
    collector.page_size = max(int(args.threatbook_page_size or collector.page_size), 1)
    if args.max_pages > 0:
        collector.max_pages = args.max_pages

    before_total = Vulnerability.query.count()
    before_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
    started_at = time.monotonic()
    print(
        f"[start] source={collector.source_name} total_before={before_total} "
        f"source_before={before_source_total} page_size={collector.page_size} "
        f"max_pages={collector.max_pages} sleep={collector.request_interval_seconds} overwrite_existing=True",
        flush=True,
    )

    total_pages = None
    fetched_records = 0
    inserted_total = 0
    updated_total = 0
    notification_total = 0

    page_index = 1
    while collector.max_pages <= 0 or page_index <= collector.max_pages:
        payload = collector.fetch_notice_page(page_index)
        data = payload.get("data") or {}
        rows = data.get("items") or []
        if not rows:
            break

        if total_pages is None:
            total_pages = int(data.get("total_pages") or 0) or None

        records = [collector.normalize_notice_item(item) for item in rows if isinstance(item, dict)]
        inserted, updated, notification_targets = upsert_vulnerabilities(records)
        db.session.commit()
        db.remove()

        fetched_records += len(records)
        inserted_total += inserted
        updated_total += updated
        notification_total += len(notification_targets)
        print(
            f"[page] source={collector.source_name} page={page_index} page_items={len(rows)} "
            f"fetched={fetched_records} inserted={inserted_total} updated={updated_total} "
            f"notification_candidates={notification_total} total_pages={total_pages or '?'}",
            flush=True,
        )

        if total_pages is not None and page_index >= total_pages:
            break
        if len(rows) < collector.page_size:
            break
        page_index += 1

    after_total = Vulnerability.query.count()
    after_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
    elapsed = time.monotonic() - started_at
    print(
        f"[done] source={collector.source_name} fetched={fetched_records} inserted={inserted_total} "
        f"updated={updated_total} notification_candidates={notification_total} "
        f"total_before={before_total} total_after={after_total} "
        f"source_before={before_source_total} source_after={after_source_total} "
        f"elapsed_seconds={elapsed:.1f}",
        flush=True,
    )


def run_seebug(args: argparse.Namespace) -> None:
    collector = SeebugCollector()
    collector.request_interval_seconds = max(float(args.sleep_seconds or 0), 0.0)
    if args.max_pages > 0:
        collector.max_pages = args.max_pages
    else:
        collector.max_pages = 0

    before_total = Vulnerability.query.count()
    before_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
    started_at = time.monotonic()
    print(
        f"[start] source={collector.source_name} total_before={before_total} "
        f"source_before={before_source_total} page_size={collector.page_size} "
        f"max_pages={collector.max_pages or 'auto'} sleep={collector.request_interval_seconds} overwrite_existing=True",
        flush=True,
    )

    total_pages = None
    fetched_records = 0
    inserted_total = 0
    updated_total = 0
    notification_total = 0

    page_index = 1
    while collector.max_pages <= 0 or page_index <= collector.max_pages:
        _, rows, detected_total_pages = collector.fetch_list_page(page_index)
        if not rows:
            break
        if total_pages is None and detected_total_pages:
            total_pages = detected_total_pages

        records = []
        for row in rows:
            published_at = parse_datetime_value("".join(row.xpath("./td[2]//text()")))
            records.append(collector._parse_row(row, published_at))

        inserted, updated, notification_targets = upsert_vulnerabilities(records)
        db.session.commit()
        db.remove()

        fetched_records += len(records)
        inserted_total += inserted
        updated_total += updated
        notification_total += len(notification_targets)
        print(
            f"[page] source={collector.source_name} page={page_index} page_items={len(rows)} "
            f"fetched={fetched_records} inserted={inserted_total} updated={updated_total} "
            f"notification_candidates={notification_total} total_pages={total_pages or '?'}",
            flush=True,
        )

        if total_pages is not None and page_index >= total_pages:
            break
        page_index += 1

    after_total = Vulnerability.query.count()
    after_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
    elapsed = time.monotonic() - started_at
    print(
        f"[done] source={collector.source_name} fetched={fetched_records} inserted={inserted_total} "
        f"updated={updated_total} notification_candidates={notification_total} "
        f"total_before={before_total} total_after={after_total} "
        f"source_before={before_source_total} source_after={after_source_total} "
        f"elapsed_seconds={elapsed:.1f}",
        flush=True,
    )


def run_venustech(args: argparse.Namespace) -> None:
    collector = VenustechCollector()
    collector.request_interval_seconds = max(float(args.sleep_seconds or 0), 0.0)
    if args.max_pages > 0:
        collector.max_pages = args.max_pages
    else:
        collector.max_pages = 0

    before_total = Vulnerability.query.count()
    before_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
    started_at = time.monotonic()
    print(
        f"[start] source={collector.source_name} total_before={before_total} "
        f"source_before={before_source_total} max_pages={collector.max_pages or 'auto'} "
        f"sleep={collector.request_interval_seconds} overwrite_existing=True",
        flush=True,
    )

    seen_urls = set()
    fetched_records = 0
    inserted_total = 0
    updated_total = 0
    notification_total = 0

    page_index = 1
    while collector.max_pages <= 0 or page_index <= collector.max_pages:
        links = collector.fetch_list_page(page_index, seen_urls=seen_urls)
        if not links:
            break

        records = [collector._fetch_detail(detail_url) for detail_url in links]
        inserted, updated, notification_targets = upsert_vulnerabilities(records)
        db.session.commit()
        db.remove()

        fetched_records += len(records)
        inserted_total += inserted
        updated_total += updated
        notification_total += len(notification_targets)
        print(
            f"[page] source={collector.source_name} page={page_index} page_items={len(links)} "
            f"fetched={fetched_records} inserted={inserted_total} updated={updated_total} "
            f"notification_candidates={notification_total}",
            flush=True,
        )
        page_index += 1

    after_total = Vulnerability.query.count()
    after_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
    elapsed = time.monotonic() - started_at
    print(
        f"[done] source={collector.source_name} fetched={fetched_records} inserted={inserted_total} "
        f"updated={updated_total} notification_candidates={notification_total} "
        f"total_before={before_total} total_after={after_total} "
        f"source_before={before_source_total} source_after={after_source_total} "
        f"elapsed_seconds={elapsed:.1f}",
        flush=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
