#!/usr/bin/env python3
from __future__ import annotations

import argparse
import calendar
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.models import Vulnerability
from seceventmonitor.services.collectors.nvd import NvdCollector
from seceventmonitor.services.sync_service import _apply_vulnerability_data


@dataclass
class WindowStats:
    fetched: int = 0
    normalized: int = 0
    inserted: int = 0
    skipped_existing: int = 0
    skipped_rejected: int = 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Backfill missing NVD CVEs month-by-month in reverse order without translation.",
    )
    parser.add_argument("--start-year", type=int, default=2015)
    parser.add_argument("--page-size", type=int, default=2000)
    parser.add_argument("--sleep-seconds", type=float, default=0.7)
    parser.add_argument("--max-retries", type=int, default=6)
    parser.add_argument("--max-months", type=int, default=0)
    return parser.parse_args()


def reverse_month_windows(start_year: int):
    now = datetime.now(UTC)
    year = now.year
    month = now.month

    while year > start_year or (year == start_year and month >= 1):
        month_start = datetime(year, month, 1, tzinfo=UTC)
        if year == now.year and month == now.month:
            month_end = now
        else:
            days_in_month = calendar.monthrange(year, month)[1]
            month_end = datetime(year, month, days_in_month, 23, 59, 59, 999000, tzinfo=UTC)
        yield month_start, month_end
        if month == 1:
            year -= 1
            month = 12
        else:
            month -= 1


def main() -> int:
    args = parse_args()
    create_app()

    collector = NvdCollector()
    api_key = (collector.settings.get("nvd_api_key") or "").strip()
    if not api_key:
        print("ERROR: database setting 'nvd_api_key' is empty.", file=sys.stderr)
        return 2

    before_total = Vulnerability.query.count()
    before_nvd = Vulnerability.query.filter_by(source="NVD").count()
    print(
        f"[start] total={before_total} nvd={before_nvd} "
        f"start_year={args.start_year} reverse_order=month_desc "
        f"page_size={args.page_size} sleep={args.sleep_seconds}",
        flush=True,
    )

    total_windows = 0
    total_stats = WindowStats()
    started_at = time.monotonic()

    try:
        for window_start, window_end in reverse_month_windows(args.start_year):
            if args.max_months and total_windows >= args.max_months:
                break
            total_windows += 1
            stats = process_window(
                collector=collector,
                window_start=window_start,
                window_end=window_end,
                page_size=args.page_size,
                sleep_seconds=args.sleep_seconds,
                max_retries=args.max_retries,
            )
            total_stats.fetched += stats.fetched
            total_stats.normalized += stats.normalized
            total_stats.inserted += stats.inserted
            total_stats.skipped_existing += stats.skipped_existing
            total_stats.skipped_rejected += stats.skipped_rejected
            print(
                "[month] "
                f"{window_start.date()}..{window_end.date()} "
                f"fetched={stats.fetched} normalized={stats.normalized} "
                f"inserted={stats.inserted} existing={stats.skipped_existing} "
                f"rejected={stats.skipped_rejected}",
                flush=True,
            )
    finally:
        db.remove()

    after_total = Vulnerability.query.count()
    after_nvd = Vulnerability.query.filter_by(source="NVD").count()
    elapsed = time.monotonic() - started_at
    print(
        "[done] "
        f"windows={total_windows} fetched={total_stats.fetched} normalized={total_stats.normalized} "
        f"inserted={total_stats.inserted} existing={total_stats.skipped_existing} "
        f"rejected={total_stats.skipped_rejected} elapsed_seconds={elapsed:.1f} "
        f"total_before={before_total} total_after={after_total} "
        f"nvd_before={before_nvd} nvd_after={after_nvd}",
        flush=True,
    )
    return 0


def process_window(
    *,
    collector: NvdCollector,
    window_start: datetime,
    window_end: datetime,
    page_size: int,
    sleep_seconds: float,
    max_retries: int,
) -> WindowStats:
    stats = WindowStats()
    start_index = 0
    page_number = 0
    total_results = None

    while True:
        page_number += 1
        payload = fetch_page(
            collector=collector,
            window_start=window_start,
            window_end=window_end,
            page_size=page_size,
            start_index=start_index,
            max_retries=max_retries,
        )
        vulnerabilities = payload.get("vulnerabilities") or []
        if total_results is None:
            total_results = int(payload.get("totalResults") or 0)

        if not vulnerabilities:
            break

        stats.fetched += len(vulnerabilities)
        normalized_records = []
        cve_ids = []
        vuln_keys = []

        for entry in vulnerabilities:
            cve = entry.get("cve") or {}
            if (cve.get("vulnStatus") or "").strip().lower() == "rejected":
                stats.skipped_rejected += 1
                continue
            item = collector._normalize_cve(cve)
            normalized_records.append(item)
            cve_ids.append(item["cve_id"])
            vuln_keys.append(item["vuln_key"])

        stats.normalized += len(normalized_records)
        existing_vuln_keys = query_existing_vuln_keys(vuln_keys)
        existing_cve_ids = query_existing_cve_ids(cve_ids)

        for item in normalized_records:
            if item["vuln_key"] in existing_vuln_keys or item["cve_id"] in existing_cve_ids:
                stats.skipped_existing += 1
                continue
            vulnerability = Vulnerability(vuln_key=item["vuln_key"])
            _apply_vulnerability_data(vulnerability, item)
            vulnerability.status = "new"
            db.session.add(vulnerability)
            stats.inserted += 1

        db.session.commit()
        print(
            "[page] "
            f"{window_start.date()}..{window_end.date()} "
            f"page={page_number} start_index={start_index} "
            f"page_items={len(vulnerabilities)} total_results={total_results} "
            f"inserted_so_far={stats.inserted} existing_so_far={stats.skipped_existing}",
            flush=True,
        )

        start_index += len(vulnerabilities)
        if start_index >= total_results:
            break
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)

    return stats


def fetch_page(
    *,
    collector: NvdCollector,
    window_start: datetime,
    window_end: datetime,
    page_size: int,
    start_index: int,
    max_retries: int,
) -> dict:
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            response = collector.session.get(
                collector.api_url,
                params={
                    "pubStartDate": collector.to_utc_iso(window_start),
                    "pubEndDate": collector.to_utc_iso(window_end),
                    "resultsPerPage": page_size,
                    "startIndex": start_index,
                },
                timeout=collector.timeout,
            )
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait_seconds = float(retry_after) if retry_after else min(60.0, attempt * 5.0)
                print(
                    f"[retry] 429 for window {window_start.date()}..{window_end.date()} "
                    f"start_index={start_index} wait={wait_seconds:.1f}s attempt={attempt}/{max_retries}",
                    flush=True,
                )
                time.sleep(wait_seconds)
                continue
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            last_error = exc
            if attempt >= max_retries:
                break
            wait_seconds = min(60.0, attempt * 5.0)
            print(
                f"[retry] error={exc} window={window_start.date()}..{window_end.date()} "
                f"start_index={start_index} wait={wait_seconds:.1f}s attempt={attempt}/{max_retries}",
                flush=True,
            )
            time.sleep(wait_seconds)

    raise RuntimeError(
        f"failed to fetch NVD page for {window_start.date()}..{window_end.date()} "
        f"start_index={start_index}: {last_error}"
    )


def query_existing_vuln_keys(vuln_keys: list[str]) -> set[str]:
    if not vuln_keys:
        return set()
    rows = db.session.query(Vulnerability.vuln_key).filter(Vulnerability.vuln_key.in_(vuln_keys)).all()
    return {row[0] for row in rows}


def query_existing_cve_ids(cve_ids: list[str]) -> set[str]:
    if not cve_ids:
        return set()
    rows = db.session.query(Vulnerability.cve_id).filter(Vulnerability.cve_id.in_(cve_ids)).all()
    return {row[0] for row in rows}


if __name__ == "__main__":
    raise SystemExit(main())
