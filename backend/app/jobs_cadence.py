from apscheduler.schedulers.asyncio import AsyncIOScheduler
import datetime as dt
from .database import SessionLocal
from .db import models
from apscheduler.jobstores.base import JobLookupError
import logging
from .job import job_update_scores


log = logging.getLogger("cadence")
FAST_SEC = 37   
MED_SEC  = 60    
SLOW_SEC = 240
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
scheduler = AsyncIOScheduler()
def cadence_manager_job():
    with SessionLocal() as db:
        now = dt.datetime.utcnow()

        live = (
            db.query(models.Match)
              .filter(models.Match.status == "live")
              .count()
        )
        soon = (
            db.query(models.Match)
              .filter(models.Match.status == "scheduled")
              .filter(models.Match.match_date.between(
                  now - dt.timedelta(minutes=30),
                  now + dt.timedelta(minutes=30)
              ))
              .count()
        )

    interval = FAST_SEC if live > 0 else (MED_SEC if soon > 0 else SLOW_SEC)

    try:
        scheduler.reschedule_job("update_scores", trigger="interval", seconds=interval)
        log.info("rescheduled update_scores to every %ss (live=%s, soon=%s)", interval, live, soon)
    except JobLookupError:
        scheduler.add_job(
            job_update_scores,
            "interval",
            seconds=interval,
            id="update_scores",
            next_run_time=dt.datetime.utcnow(),
        )
        log.info("scheduled update_scores every %ss (first run now)", interval)