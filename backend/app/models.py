from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from .database import Base


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

class Prediction(Base):
    __tablename__ = "predictions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    match_id = Column(Integer, ForeignKey("matches.id"))
    predicted_winner = Column(String)
    predicted_diff = Column(Integer)

    user = relationship("User")
    match = relationship("Match")
class TestUser(Base):
    __tablename__ = "test_users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)