#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.models import PushLog, Vulnerability, VulnerabilityEvent
from seceventmonitor.services.collectors.venustech import VenustechCollector
from seceventmonitor.services.sync_service import upsert_vulnerabilities


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clear existing Venustech vulnerabilities and backfill all Venustech advisories since the specified year.",
    )
    parser.add_argument("--start-year", type=int, default=2022, help="Only keep advisories published on or after this year.")
    parser.add_argument("--max-pages", type=int, default=0, help="Optional page cap for debugging.")
    parser.add_argument("--sleep-seconds", type=float, default=0.0, help="Delay between HTTP requests.")
    parser.add_argument(
        "--skip-clear",
        action="store_true",
        help="Do not clear existing Venustech rows before backfill; existing rows will be overwritten by upsert.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    create_app()

    collector = VenustechCollector()
    collector.request_interval_seconds = max(float(args.sleep_seconds or 0), 0.0)
    page_limit = int(args.max_pages or 0)
    threshold = datetime(max(int(args.start_year), 1970), 1, 1, tzinfo=UTC)

    before_total = Vulnerability.query.count()
    before_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
    cleared = 0
    if not args.skip_clear:
        cleared = clear_existing_venustech_rows(collector.source_name)

    started_at = time.monotonic()
    print(
        f"[start] source={collector.source_name} total_before={before_total} "
        f"source_before={before_source_total} cleared={cleared} "
        f"start_year={args.start_year} max_pages={page_limit or 'auto'} "
        f"sleep={collector.request_interval_seconds} overwrite_existing=True",
        flush=True,
    )

    seen_urls: set[str] = set()
    page_index = 1
    fetched_records = 0
    inserted_total = 0
    updated_total = 0
    notification_total = 0
    skipped_errors = 0

    try:
        while page_limit <= 0 or page_index <= page_limit:
            links = collector.fetch_list_page(page_index, seen_urls=seen_urls)
            if not links:
                break

            records = []
            reached_threshold = False
            for detail_url in links:
                try:
                    record = collector._fetch_detail(detail_url)
                except Exception as exc:
                    skipped_errors += 1
                    print(
                        f"[warn] source={collector.source_name} page={page_index} url={detail_url} error={exc}",
                        flush=True,
                    )
                    continue
                compare_time = record.get("last_seen_at") or record.get("published_at")
                if compare_time is not None and compare_time < threshold:
                    reached_threshold = True
                    continue
                records.append(record)

            inserted = 0
            updated = 0
            notification_targets = []
            if records:
                inserted, updated, notification_targets = upsert_vulnerabilities(records)
                db.session.commit()
            else:
                db.session.rollback()
            db.remove()

            fetched_records += len(records)
            inserted_total += inserted
            updated_total += updated
            notification_total += len(notification_targets)
            print(
                f"[page] source={collector.source_name} page={page_index} page_items={len(links)} "
                f"in_range={len(records)} fetched={fetched_records} inserted={inserted_total} "
                f"updated={updated_total} notification_candidates={notification_total} "
                f"reached_threshold={reached_threshold} skipped_errors={skipped_errors}",
                flush=True,
            )

            if reached_threshold:
                break
            page_index += 1
    finally:
        db.remove()

    after_total = Vulnerability.query.count()
    after_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
    elapsed = time.monotonic() - started_at
    print(
        f"[done] source={collector.source_name} fetched={fetched_records} inserted={inserted_total} "
        f"updated={updated_total} notification_candidates={notification_total} "
        f"skipped_errors={skipped_errors} "
        f"total_before={before_total} total_after={after_total} "
        f"source_before={before_source_total} source_after={after_source_total} "
        f"elapsed_seconds={elapsed:.1f}",
        flush=True,
    )
    return 0


def clear_existing_venustech_rows(source_name: str) -> int:
    vulnerabilities = Vulnerability.query.filter_by(source=source_name).all()
    vulnerability_ids = [item.id for item in vulnerabilities]
    if not vulnerability_ids:
        db.session.rollback()
        return 0

    VulnerabilityEvent.query.filter(VulnerabilityEvent.vulnerability_id.in_(vulnerability_ids)).delete(
        synchronize_session=False
    )
    PushLog.query.filter(PushLog.vulnerability_id.in_(vulnerability_ids)).delete(synchronize_session=False)
    Vulnerability.query.filter(Vulnerability.id.in_(vulnerability_ids)).delete(synchronize_session=False)
    db.session.commit()
    db.remove()
    return len(vulnerability_ids)


if __name__ == "__main__":
    raise SystemExit(main())
