from pydantic import BaseModel, EmailStr
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
    date: Optional[datetime] = None  # stored in UTC in DB; convert on the client if needed
    status: Optional[str] = None
    source: Optional[str] = None
    season: Optional[int] = None

    class Config:
        orm_mode = True  # Pydantic v1 compatible
        
class PredictionOut(BaseModel):
    id: int
    match_id: int
    user_id: str
    pick: Optional[Literal["home", "away"]]
    margin: Optional[int]
    points_awarded: int
    is_final: bool
    created_at: dt.datetime
    updated_at: dt.datetime

    class Config:
        orm_mode = True
        
class PredictionCreate(PredictionBase):
    match_id: int