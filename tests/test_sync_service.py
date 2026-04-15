import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from seceventmonitor import create_app
from seceventmonitor.extensions import db
from seceventmonitor.services import sync_service


class CnnvdSyncStrategyTest(unittest.TestCase):
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

    def test_cnnvd_incremental_sync_uses_existing_code_boundary_instead_of_time_filter(self) -> None:
        captured = {}

        class FakeCollector:
            def iter_batches(self, **kwargs):
                captured.update(kwargs)
                if False:
                    yield []

        job_id = sync_service._create_job("cnnvd", status="queued", message="等待测试")

        with patch.object(
            sync_service,
            "get_last_success_time",
            return_value=datetime(2026, 4, 13, 2, 50, 9, tzinfo=UTC),
        ):
            with patch.dict(sync_service.COLLECTOR_MAP, {"cnnvd": FakeCollector}):
                result = sync_service._run_cnnvd_source(job_id)

        self.assertEqual(result["status"], "success")
        self.assertIsNone(captured["since"])
        self.assertTrue(captured["full_history"])
        self.assertTrue(captured["stop_on_existing"])

    def test_cnnvd_first_sync_keeps_non_full_history_mode(self) -> None:
        captured = {}

        class FakeCollector:
            def iter_batches(self, **kwargs):
                captured.update(kwargs)
                if False:
                    yield []

        job_id = sync_service._create_job("cnnvd", status="queued", message="等待测试")

        with patch.object(sync_service, "get_last_success_time", return_value=None):
            with patch.dict(sync_service.COLLECTOR_MAP, {"cnnvd": FakeCollector}):
                result = sync_service._run_cnnvd_source(job_id)

        self.assertEqual(result["status"], "success")
        self.assertIsNone(captured["since"])
        self.assertFalse(captured["full_history"])
        self.assertFalse(captured["stop_on_existing"])


if __name__ == "__main__":
    unittest.main()
