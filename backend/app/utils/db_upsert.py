# app/utils/db_upsert.py
from typing import List, Dict
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert as pg_insert
from .. import models

IMMUTABLE_COLS = {"id"}  # don't overwrite PK

def bulk_upsert_by_external_id(db: Session, rows: List[Dict]):
    if not rows:
        return
    dialect = db.bind.dialect.name if db.bind and db.bind.dialect else "unknown"

    # Deduplicate within the same batch by external_id (keep the last one)
    dedup = {}
    for r in rows:
        ext = r.get("external_id")
        if not ext:
            continue
        dedup[ext] = r
    rows = list(dedup.values())

    if dialect == "postgresql":
        stmt = pg_insert(models.Match).values(rows)
        update_cols = {
            c.name: getattr(stmt.excluded, c.name)
            for c in models.Match.__table__.columns
            if c.name not in IMMUTABLE_COLS
        }
        stmt = stmt.on_conflict_do_update(
            index_elements=[models.Match.external_id],
            set_=update_cols,
        )
        db.execute(stmt)
    else:
        # Generic fallback: read existing external_ids then update/insert row-by-row
        ext_ids = [r["external_id"] for r in rows if r.get("external_id")]
        if not ext_ids:
            return
        existing = set(
            x[0]
            for x in db.query(models.Match.external_id)
                       .filter(models.Match.external_id.in_(ext_ids))
                       .all()
        )
        for r in rows:
            ext = r.get("external_id")
            if not ext:
                continue
            if ext in existing:
                m = db.query(models.Match).filter(models.Match.external_id == ext).first()
                for k, v in r.items():
                    if k not in IMMUTABLE_COLS:
                        setattr(m, k, v)
            else:
                db.add(models.Match(**r))
