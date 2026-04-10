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
from seceventmonitor.services.collectors.oscs import OscsCollector
from seceventmonitor.services.sync_service import upsert_vulnerabilities


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Backfill the full OSCS intelligence history and overwrite existing database rows.",
    )
    parser.add_argument("--max-pages", type=int, default=0, help="Optional page cap for debugging.")
    parser.add_argument("--page-size", type=int, default=50, help="Per-page size for OSCS list API.")
    parser.add_argument("--sleep-seconds", type=float, default=2.0, help="Delay between HTTP requests.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    create_app()

    collector = OscsCollector()
    if args.max_pages > 0:
        collector.max_pages = args.max_pages
    collector.page_size = max(int(args.page_size or collector.page_size), 1)
    collector.request_interval_seconds = max(float(args.sleep_seconds or 0), 0.0)

    before_total = Vulnerability.query.count()
    before_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
    started_at = time.monotonic()

    print(
        f"[start] source={collector.source_name} total_before={before_total} "
        f"source_before={before_source_total} page_size={collector.page_size} "
        f"max_pages={collector.max_pages} sleep={collector.request_interval_seconds} "
        f"full_history=True overwrite_existing=True",
        flush=True,
    )

    try:
        records = collector.fetch(
            since=None,
            progress_callback=_progress_callback,
            full_history=True,
            stop_on_existing=False,
        )
        print(f"[fetch] fetched_records={len(records)}", flush=True)
        inserted, updated, notification_targets = upsert_vulnerabilities(records)
        db.session.commit()
        after_total = Vulnerability.query.count()
        after_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
        elapsed = time.monotonic() - started_at
        print(
            f"[done] inserted={inserted} updated={updated} notification_candidates={len(notification_targets)} "
            f"total_before={before_total} total_after={after_total} "
            f"source_before={before_source_total} source_after={after_source_total} "
            f"elapsed_seconds={elapsed:.1f}",
            flush=True,
        )
        return 0
    finally:
        db.remove()


def _progress_callback(page_index: int, page_size: int, fetched_count: int, total_results=None) -> None:
    total_display = total_results if total_results is not None else "?"
    print(
        f"[page] page={page_index} page_size={page_size} fetched={fetched_count} total={total_display}",
        flush=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
