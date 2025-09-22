from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from .job import set_scheduler,schedule_bots_for_all_future,job_update_scores,job_ws_reminders_one_hour,job_seed_future,job_housekeeping
from app.routers import euroleague_stats
from .db import models, schemas
from app.routers import team_season
from .routers import auth, getGames, internal_jobs, predictions, groups, leaderboard, ws, me, adminFix
from .core import database
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from .routers.auth import get_current_user
import os, logging
from .db.migrations import ensure_match_columns
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from .job import job_update_scores, job_settle_ready, job_seed_future, job_ws_reminders_one_hour, job_housekeeping
from .core.constants import AppConstants, HTTPStatus, ErrorMessages
from .jobs_cadence import cadence_manager_job
from app.routers import teams
from app.routers import league_overview
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from app.routers import match_full
models.Base.metadata.create_all(bind=database.engine)
ensure_match_columns(database.engine)
logger = logging.getLogger("uvicorn")
scheduler = AsyncIOScheduler(timezone="UTC")
app = FastAPI()
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:5175"],  # Add your frontend URLs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(match_full.router)
app.include_router(euroleague_stats.router)
app.include_router(groups.router)
app.include_router(leaderboard.router)
app.include_router(auth.router)
app.include_router(getGames.router)
app.include_router(internal_jobs.router)
app.include_router(predictions.router)
app.include_router(ws.router)
app.include_router(me.router)
app.include_router(adminFix.router)
app.include_router(teams.router)
app.include_router(team_season.router)
app.include_router(league_overview.router)
# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]        
@app.get("/",status_code=HTTPStatus.OK)
async def user(user:user_dependency, db:db_dependency):
    if user is None:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail=ErrorMessages.NOT_AUTHENTICATED)
    return {"User": user}

def start_scheduler():
    if os.getenv("RUN_SCHEDULER") == "1":
        set_scheduler(scheduler)

        scheduler.add_job(job_update_scores, "interval",
                          seconds=AppConstants.SLOW_SEC, id="update_scores")
        scheduler.add_job(cadence_manager_job, "interval",
                          seconds=180, id="cadence_manager")
        scheduler.add_job(job_ws_reminders_one_hour, "interval",
                          seconds=60, id="ws_reminders_1h")

        scheduler.add_job(job_seed_future, "cron",
                          minute=30, id="seed_future_daily")
        scheduler.add_job(job_housekeeping, "cron",
                          hour=3, id="housekeeping_daily")

        schedule_bots_for_all_future(scheduler)

        if not scheduler.running:
            scheduler.start()
        print("start_scheduler")
        

@app.on_event("startup")
async def on_startup():
    start_scheduler()
    
# def home():
#     return {"message": "Fantasy API running! dash leShimi"}

# @app.post("/register", response_model=schemas.UserResponse)
# def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
#     # Check if email already exists
#     if db.query(models.User).filter(models.User.email == user.email).first():
#         raise HTTPException(status_code=400, detail="Email already registered")
#     if db.query(models.User).filter(models.User.username == user.username).first():
#         raise HTTPException(status_code=400, detail="Username already taken")

#     hashed_pw = auth.hash_password(user.password)
#     new_user = models.User(username=user.username, email=user.email, hashed_password=hashed_pw)
#     db.add(new_user)
#     db.commit()
#     db.refresh(new_user)
#     return new_user

# @app.post("/login", response_model=schemas.Token)
# def login(user_data: schemas.UserLogin, db: Session = Depends(get_db)):
#     user = db.query(models.User).filter(models.User.email == user_data.email).first()
#     if not user or not auth.verify_password(user_data.password, user.hashed_password):
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

#     access_token = auth.create_access_token(data={"sub": user.email})
#     return {"access_token": access_token, "token_type": "bearer"}
# @app.get("/me", response_model=schemas.UserResponse)
# def read_me(current_user: models.User = Depends(get_current_user)):
#     return current_user
# @app.post("/logout")
# def logout():
#     # On JWT systems without a blacklist, logout is just deleting the token client-side.
#     return {"message": "Successfully logged out. Please delete your token on the client side."}


