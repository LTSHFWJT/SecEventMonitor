from seceventmonitor.extensions import db
from seceventmonitor.models.base import TimestampMixin


class KevCatalogEntry(db.Model, TimestampMixin):
    __tablename__ = "kev_catalog_entries"

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(64), unique=True, nullable=False, index=True)

