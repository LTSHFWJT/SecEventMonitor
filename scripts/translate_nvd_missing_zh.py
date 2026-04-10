#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Integer, and_, cast, func, or_

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.models import Vulnerability
from seceventmonitor.services.translation_api_service import list_enabled_translation_api_configs
from seceventmonitor.services.translation_service import infer_translation_language, translate_text_to_zh


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Translate missing Chinese description/remediation for NVD vulnerabilities.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of NVD vulnerabilities to process.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.limit <= 0:
        print("ERROR: --limit must be greater than 0.", file=sys.stderr)
        return 2

    create_app()

    enabled_configs = list_enabled_translation_api_configs()
    if not enabled_configs:
        print("ERROR: no enabled translation API configs found.", file=sys.stderr)
        db.remove()
        return 2

    candidates = build_candidate_query().limit(args.limit).all()
    if not candidates:
        print("[done] no matching NVD vulnerabilities need translation.", flush=True)
        db.remove()
        return 0

    print(
        f"[start] source=NVD limit={args.limit} candidates={len(candidates)} order=cve_desc",
        flush=True,
    )

    processed = 0
    translated_vulnerabilities = 0
    translated_descriptions = 0
    translated_remediations = 0
    unchanged = 0

    try:
        for vulnerability in candidates:
            processed += 1
            cve_id = (vulnerability.cve_id or "").strip() or f"id:{vulnerability.id}"
            print(f"[translate] cve={cve_id}", flush=True)

            description_updated = translate_missing_description(vulnerability)
            remediation_updated = translate_missing_remediation(vulnerability)

            if description_updated or remediation_updated:
                db.session.commit()
                translated_vulnerabilities += 1
                translated_descriptions += int(description_updated)
                translated_remediations += int(remediation_updated)
                print(
                    f"[saved] cve={cve_id} "
                    f"description={'yes' if description_updated else 'no'} "
                    f"remediation={'yes' if remediation_updated else 'no'}",
                    flush=True,
                )
            else:
                db.session.commit()
                unchanged += 1
                print(
                    f"[skip] cve={cve_id} no_translated_fields_saved",
                    flush=True,
                )
    finally:
        db.remove()

    print(
        "[done] "
        f"processed={processed} translated_vulnerabilities={translated_vulnerabilities} "
        f"translated_descriptions={translated_descriptions} "
        f"translated_remediations={translated_remediations} "
        f"unchanged={unchanged}",
        flush=True,
    )
    return 0


def build_candidate_query():
    missing_description = and_(
        func.trim(func.coalesce(Vulnerability.description, "")) != "",
        func.trim(func.coalesce(Vulnerability.translated_description, "")) == "",
    )
    missing_remediation = and_(
        func.trim(func.coalesce(Vulnerability.remediation, "")) != "",
        func.trim(func.coalesce(Vulnerability.translated_remediation, "")) == "",
    )
    return (
        Vulnerability.query.filter(func.upper(Vulnerability.source) == "NVD")
        .filter(func.upper(Vulnerability.cve_id).like("CVE-%-%"))
        .filter(or_(missing_description, missing_remediation))
        .order_by(
            cast(func.substr(Vulnerability.cve_id, 5, 4), Integer).desc(),
            cast(func.substr(Vulnerability.cve_id, 10), Integer).desc(),
            Vulnerability.id.desc(),
        )
    )


def translate_missing_description(vulnerability: Vulnerability) -> bool:
    description = (vulnerability.description or "").strip()
    translated_description = (vulnerability.translated_description or "").strip()
    if not description or translated_description:
        return False

    source_language = infer_translation_language(description, vulnerability.description_lang)
    translated = translate_text_to_zh(description, source_language)
    if not translated:
        return False

    vulnerability.translated_description = translated
    vulnerability.translated_at = datetime.now(UTC).replace(tzinfo=None)
    return True


def translate_missing_remediation(vulnerability: Vulnerability) -> bool:
    remediation = (vulnerability.remediation or "").strip()
    translated_remediation = (vulnerability.translated_remediation or "").strip()
    if not remediation or translated_remediation:
        return False

    source_language = infer_translation_language(remediation, vulnerability.description_lang)
    translated = translate_text_to_zh(remediation, source_language)
    if not translated:
        return False

    vulnerability.translated_remediation = translated
    vulnerability.translated_remediation_at = datetime.now(UTC).replace(tzinfo=None)
    return True


if __name__ == "__main__":
    raise SystemExit(main())
