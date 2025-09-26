from pydantic import BaseModel, EmailStr, Field, model_validator, ConfigDict, field_validator
import datetime as dt
from typing import Optional, Literal


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    is_admin: bool

    class Config:
        from_attributes  = True
class UserLogin(BaseModel):
    email: EmailStr
    password: str
class Token(BaseModel):
    access_token: str
    token_type: str

from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class NextGameOut(BaseModel):
    id: int
    external_id: Optional[str] = None
    league: Optional[str] = None
    home: Optional[str] = None
    away: Optional[str] = None
    date: Optional[datetime] = None 
    status: Optional[str] = None
    source: Optional[str] = None
    season: Optional[int] = None

    class Config:
        from_attributes = True
        
class PredictionBase(BaseModel):
    pick: Optional[Literal["home", "away"]] = Field(None, description="Winner pick; must be null when margin=0")
    margin: int = Field(..., ge=0, description="Points margin; 0 disables the prediction")

    @model_validator(mode="before") 
    def _winner_margin_consistency(cls, values):
        pick, margin = values.get("pick"), values.get("margin")
        if margin == 0 and pick is not None:
            raise ValueError("When margin=0, pick must be null (prediction disabled).")
        if margin >= 1 and pick is None:
            raise ValueError("When margin>=1, pick is required.")
        return values

class PredictionCreate(PredictionBase):
    match_id: int

class PredictionUpdate(BaseModel):
    pick: Optional[Literal["home", "away"]] = None
    margin: Optional[int] = Field(None, ge=0)

class PredictionOut(BaseModel):
    id: int
    match_id: int
    user_id: int
    pick: Optional[Literal["home", "away"]]
    margin: int
    points_awarded: int
    is_final: bool
    created_at: dt.datetime
    updated_at: dt.datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("user_id", mode="before")
    @classmethod
    def _cast_user_id(cls, v):
        return "" if v is None else str(v)
    

class LeaderboardEntry(BaseModel):
    user_id: int
    total_points: int
    bets: int
    rank: int
    model_config = ConfigDict(from_attributes=True)

class GroupCreate(BaseModel):
    name: str
    is_private: bool = True

class GroupOut(BaseModel):
    id: int
    name: str
    owner_id: str
    invite_code: Optional[str] = None
    is_private: bool
    member_count: int
    model_config = ConfigDict(from_attributes=True)
    
    
class StandingRow(BaseModel):
    team: str
    w: int
    l: int
    pf: int
    pa: int
    diff: int
    rank: int
    
class MyGroupOut(BaseModel):
    id: int
    name: str
    role: str             
    owner_id: int
    is_private: bool
    invite_code: Optional[str] = None
    created_at: Optional[datetime] = None