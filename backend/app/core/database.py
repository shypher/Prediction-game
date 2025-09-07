# backend/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()



DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
def get_user_by_email(email: str):
    db = SessionLocal()
    try:
        return db.query(models.User).filter(models.User.email == email).first()
    finally:
        db.close()

def create_user(username: str, email: str, password: str | None = None, provider: str = "local"):
    db = SessionLocal()
    try:
        user = models.User(
            username=username,
            email=email,
            password=password,
            provider=provider
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()