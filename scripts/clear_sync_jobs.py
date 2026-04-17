#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.services.sync_service import clear_sync_jobs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clear sync job records from the database.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Delete all sync job history instead of only queued/running jobs.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="Limit deletion to one source. Accepts 'nvd' or 'sync:nvd'. Can be repeated.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    create_app()

    try:
        result = clear_sync_jobs(
            active_only=not args.all,
            sources=args.source,
        )
        source_display = ", ".join(result["job_names"]) if result["job_names"] else "all sync jobs"
        status_display = ", ".join(result["statuses"]) if result["statuses"] else "none"
        mode = "active-only" if result["active_only"] else "all-history"
        print(
            f"[done] mode={mode} deleted={result['deleted']} "
            f"job_names={source_display} statuses={status_display}",
            flush=True,
        )
        print(
            "[note] If the web process is still running and a task was stuck as busy, restart the service to clear "
            "its in-memory active-source cache.",
            flush=True,
        )
        return 0
    finally:
        db.remove()


if __name__ == "__main__":
    raise SystemExit(main())
