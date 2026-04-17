import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.models import SyncJobLog
from seceventmonitor.services import sync_service


class ClearSyncJobsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        db.remove()
        if getattr(db, "_engine", None) is not None:
            db._engine.dispose()
        os.environ["APP_SECRET_KEY"] = "test-secret"
        os.environ["SQLITE_DB_PATH"] = str(Path(self._tmpdir.name) / "test.db")
        self.app = create_app()

    def tearDown(self) -> None:
        db.remove()
        if getattr(db, "_engine", None) is not None:
            db._engine.dispose()
        os.environ.pop("APP_SECRET_KEY", None)
        os.environ.pop("SQLITE_DB_PATH", None)
        self._tmpdir.cleanup()

    def test_clear_sync_jobs_defaults_to_active_only(self) -> None:
        self._add_job("sync:nvd", "queued")
        self._add_job("sync:oscs", "running")
        self._add_job("sync:nvd", "success")
        self._add_job("manual:other", "running")

        result = sync_service.clear_sync_jobs()

        self.assertEqual(result["deleted"], 2)
        self.assertTrue(result["active_only"])
        remaining = {
            (item.job_name, item.status)
            for item in SyncJobLog.query.order_by(SyncJobLog.id.asc()).all()
        }
        self.assertEqual(
            remaining,
            {
                ("sync:nvd", "success"),
                ("manual:other", "running"),
            },
        )

    def test_clear_sync_jobs_can_target_specific_source_and_all_history(self) -> None:
        self._add_job("sync:nvd", "queued")
        self._add_job("sync:nvd", "success")
        self._add_job("sync:oscs", "failed")

        result = sync_service.clear_sync_jobs(active_only=False, sources=["nvd"])

        self.assertEqual(result["deleted"], 2)
        self.assertFalse(result["active_only"])
        self.assertEqual(result["job_names"], ["sync:nvd"])
        remaining = {
            (item.job_name, item.status)
            for item in SyncJobLog.query.order_by(SyncJobLog.id.asc()).all()
        }
        self.assertEqual(remaining, {("sync:oscs", "failed")})

    @staticmethod
    def _add_job(job_name: str, status: str) -> None:
        now = datetime.now(UTC)
        db.session.add(
            SyncJobLog(
                job_name=job_name,
                status=status,
                message=f"{job_name}:{status}",
                started_at=now,
                finished_at=None,
            )
        )
        db.session.commit()


if __name__ == "__main__":
    unittest.main()
