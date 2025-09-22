from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, text, Float
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
    
    
class Team(Base):
    __tablename__ = "teams"
    id = Column(Integer, primary_key=True, index=True)
    external_id = Column(String, index=True, nullable=True)
    league_id = Column(Integer, index=True, nullable=False)
    name = Column(String, index=True, nullable=False)
    abbreviation = Column(String, index=True, nullable=True)
    logo_url = Column(String, nullable=True)
    primary_color = Column(String, nullable=True)
    secondary_color = Column(String, nullable=True)
    country = Column(String, nullable=True)
    __table_args__ = (UniqueConstraint("league_id", "name", name="uq_team_league_name"),)

class Player(Base):
    __tablename__ = "players"
    id = Column(Integer, primary_key=True, index=True)
    external_id = Column(String, index=True, nullable=True)
    league_id = Column(Integer, index=True, nullable=False)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True)
    team = relationship("Team")

class GamePlayerStat(Base):
    __tablename__ = "game_player_stats"
    id = Column(Integer, primary_key=True, index=True)
    match_id = Column(Integer, index=True, nullable=False)
    player_id = Column(Integer, ForeignKey("players.id"), nullable=True)
    league_id = Column(Integer, index=True, nullable=False)
    pts = Column(Integer, nullable=True)
    ast = Column(Integer, nullable=True)
    reb = Column(Integer, nullable=True)
    stl = Column(Integer, nullable=True)
    blk = Column(Integer, nullable=True)
    fg3m = Column(Integer, nullable=True)
    minutes = Column(String, nullable=True)
    to = Column(Integer, nullable=True)
    plus_minus = Column(Integer, nullable=True)
    player = relationship("Player")

class TeamSeasonStat(Base):
    __tablename__ = "team_season_stats"
    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=False)
    league_id = Column(Integer, index=True, nullable=False)
    season = Column(Integer, index=True, nullable=False)
    ppg = Column(Float, nullable=True)
    apg = Column(Float, nullable=True)
    rpg = Column(Float, nullable=True)
    team = relationship("Team")
    __table_args__ = (UniqueConstraint("team_id", "season", name="uq_team_season"),)
    
    
class GameTeamStat(Base):
    __tablename__ = "game_team_stats"
    id = Column(Integer, primary_key=True)
    match_id = Column(Integer, index=True, nullable=False)
    league_id = Column(Integer, index=True, nullable=False)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=False)
    opponent_team_id = Column(Integer, ForeignKey("teams.id"), nullable=False)
    pts = Column(Integer); ast = Column(Integer); reb = Column(Integer)
    stl = Column(Integer); blk = Column(Integer); tov = Column(Integer)
    fgm = Column(Integer); fga = Column(Integer)
    fg3m = Column(Integer); fg3a = Column(Integer)
    ftm = Column(Integer); fta = Column(Integer)