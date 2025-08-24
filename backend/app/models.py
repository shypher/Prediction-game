from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from .database import Base
from sqlalchemy.dialects.postgresql import ENUM as PG_ENUM

PickEnum = PG_ENUM('home', 'away', name='pick_enum', create_type=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)


class Match(Base):
    __tablename__ = "matches"
    id = Column(Integer, primary_key=True, index=True)

    home_team = Column(String, index=True)
    away_team = Column(String, index=True)
    match_date = Column(DateTime, index=True)
    home_score = Column(Integer, nullable=True)
    away_score = Column(Integer, nullable=True)
    Round = Column("round", Integer, nullable=True)   
    league_id = Column(Integer, nullable=False)
    season = Column(Integer, nullable=False)
    external_id = Column(String, unique=True, index=True, nullable=True)
    status = Column(String, index=True, default="scheduled")
    league_name = Column(String, nullable=True)
    country = Column(String, nullable=True)
    timezone = Column(String, nullable=True)
    last_update = Column(DateTime, nullable=True)
    source = Column(String, nullable=True) 

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Enum, ForeignKey, UniqueConstraint, CheckConstraint
from sqlalchemy.orm import relationship
import datetime as dt

# אם עדיין אין לך ENUM לשימוש, נייצר אחד מקומי:
from sqlalchemy.dialects.postgresql import ENUM as PG_ENUM

PickEnum = PG_ENUM('home', 'away', name='pick_enum', create_type=False)

class Prediction(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, index=True)
    match_id = Column(Integer, ForeignKey("matches.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String, nullable=False, index=True)  
    pick = Column(PickEnum, nullable=True)  
    margin = Column(Integer, nullable=True)
    points_awarded = Column(Integer, nullable=False, default=0)
    is_final = Column(Boolean, nullable=False, default=False)  # האם הניקוד נסגר
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    match = relationship("Match", backref="predictions")

    __table_args__ = (
        UniqueConstraint("match_id", "user_id", name="uq_prediction_user_match"),
        CheckConstraint('margin >= 0', name="ck_margin_non_positive")
    )
    
    
    
class TestUser(Base):
    __tablename__ = "test_users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)