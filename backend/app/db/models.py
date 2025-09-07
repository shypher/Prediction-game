from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, text
from sqlalchemy.orm import relationship
from ..core.database import Base
from sqlalchemy.dialects.postgresql import ENUM as PG_ENUM
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Enum, ForeignKey, UniqueConstraint, CheckConstraint
from sqlalchemy.orm import relationship
import datetime as dt
from sqlalchemy.dialects.postgresql import ENUM as PG_ENUM

PickEnum = PG_ENUM('home', 'away', name='pick_enum', create_type=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    is_bot = Column(Boolean, nullable=False, default=False)
    login_disabled = Column(Boolean, nullable=False, default=False)


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


PickEnum = PG_ENUM('home', 'away', name='pick_enum', create_type=False)

class Prediction(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, index=True)
    match_id = Column(Integer, ForeignKey("matches.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)  
    pick = Column(PickEnum, nullable=True)  
    margin = Column(Integer, nullable=False, server_default="0")
    points_awarded = Column(Integer, nullable=False, default=0)
    is_final = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    match = relationship("Match", backref="predictions")

    __table_args__ = (
        UniqueConstraint("match_id", "user_id", name="uq_prediction_user_match"),
        CheckConstraint(
            "(margin = 0 AND pick IS NULL) OR (margin >= 1 AND pick IS NOT NULL)",
            name="ck_prediction_active_or_disabled",)
    )
    
    
    
class TestUser(Base):
    __tablename__ = "test_users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    
    
    
class Group(Base):
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    owner_id = Column(Integer, nullable=False, index=True)
    invite_code = Column(String, unique=True, index=True)
    is_private = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=text("NOW()"))

class GroupMember(Base):
    __tablename__ = "group_members"
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True)
    user_id = Column(Integer, primary_key=True)
    role = Column(String, nullable=False, default="member")
    joined_at = Column(DateTime(timezone=True), server_default=text("NOW()"))