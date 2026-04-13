#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.models import Vulnerability
from seceventmonitor.services.collectors.cnnvd import CnnvdCollector
from seceventmonitor.services.collectors.helpers import parse_datetime_value
from seceventmonitor.services.sync_service import upsert_vulnerabilities


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Backfill the full CNNVD vulnerability history and skip duplicate/existing CNNVD identifiers.",
    )
    parser.add_argument("--max-pages", type=int, default=0, help="Optional page cap for debugging.")
    parser.add_argument("--page-size", type=int, default=50, help="Per-page size for the CNNVD list API (max 50).")
    parser.add_argument("--sleep-seconds", type=float, default=2.0, help="Delay between HTTP requests.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    create_app()

    collector = CnnvdCollector()
    if args.max_pages > 0:
        collector.max_pages = args.max_pages
    else:
        collector.max_pages = 0
    collector.page_size = min(max(int(args.page_size or collector.page_size), 1), 50)
    collector.request_interval_seconds = max(float(args.sleep_seconds or 0), 0.0)

    before_total = Vulnerability.query.count()
    before_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
    started_at = time.monotonic()

    print(
        f"[start] source={collector.source_name} total_before={before_total} "
        f"source_before={before_source_total} page_size={collector.page_size} "
        f"max_pages={collector.max_pages} sleep={collector.request_interval_seconds} "
        "full_history=True skip_existing=True skip_duplicates=True",
        flush=True,
    )

    try:
        inserted = 0
        updated = 0
        fetched_records = 0
        notification_count = 0
        skipped_existing = 0
        skipped_duplicate = 0
        seen_vuln_keys: set[str] = set()
        page_index = 1

        while collector.max_pages <= 0 or page_index <= collector.max_pages:
            payload = collector._fetch_list_payload(page_index)
            data = payload.get("data") or {}
            rows = data.get("records") or []
            total_results = data.get("total")
            if not rows:
                break

            existing_map = collector._load_existing_vulnerabilities(rows)
            batch = []

            for row in rows:
                vuln_key = collector._build_vuln_key(row)
                if not vuln_key:
                    continue
                if vuln_key in seen_vuln_keys:
                    skipped_duplicate += 1
                    continue

                seen_vuln_keys.add(vuln_key)
                if vuln_key in existing_map:
                    skipped_existing += 1
                    continue

                detail = collector._fetch_detail(row)
                batch.append(
                    collector._normalize_item(
                        row,
                        detail,
                        published_at=parse_datetime_value(row.get("publishTime") or row.get("createTime")),
                        last_seen_at=parse_datetime_value(
                            row.get("updateTime") or row.get("createTime") or row.get("publishTime")
                        ),
                    )
                )

            _progress_callback(
                page_index=page_index,
                page_size=collector.page_size,
                fetched_count=fetched_records + len(batch),
                total_results=total_results,
                skipped_existing=skipped_existing,
                skipped_duplicate=skipped_duplicate,
            )

            if not batch and len(rows) < collector.page_size:
                break
            if not batch:
                page_index += 1
                continue

            fetched_records += len(batch)
            batch_inserted, batch_updated, notification_targets = upsert_vulnerabilities(batch)
            inserted += batch_inserted
            updated += batch_updated
            notification_count += len(notification_targets)
            db.session.commit()
            print(
                f"[commit] fetched={fetched_records} inserted={inserted} updated={updated} "
                f"notification_candidates={notification_count} skipped_existing={skipped_existing} "
                f"skipped_duplicate={skipped_duplicate}",
                flush=True,
            )
            if len(rows) < collector.page_size:
                break
            page_index += 1

        after_total = Vulnerability.query.count()
        after_source_total = Vulnerability.query.filter_by(source=collector.source_name).count()
        elapsed = time.monotonic() - started_at
        print(
            f"[done] inserted={inserted} updated={updated} notification_candidates={notification_count} "
            f"skipped_existing={skipped_existing} skipped_duplicate={skipped_duplicate} "
            f"total_before={before_total} total_after={after_total} "
            f"source_before={before_source_total} source_after={after_source_total} "
            f"elapsed_seconds={elapsed:.1f}",
            flush=True,
        )
        return 0
    finally:
        db.remove()


def _progress_callback(
    page_index: int,
    page_size: int,
    fetched_count: int,
    total_results=None,
    skipped_existing: int = 0,
    skipped_duplicate: int = 0,
) -> None:
    total_display = total_results if total_results is not None else "?"
    total_pages = "?"
    if total_results is not None and page_size:
        total_pages = math.ceil(total_results / page_size)
    print(
        f"[page] page={page_index}/{total_pages} page_size={page_size} fetched={fetched_count} "
        f"total={total_display} skipped_existing={skipped_existing} skipped_duplicate={skipped_duplicate}",
        flush=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
