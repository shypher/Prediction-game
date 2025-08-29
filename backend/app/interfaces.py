from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime, date

# User Interface
class IUserService(ABC):
    @abstractmethod
    def create_user(self, username: str, email: str, password: str) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def is_admin(self, user_id: int) -> bool:
        pass

# Match Interface
class IMatchService(ABC):
    @abstractmethod
    def get_match_by_id(self, match_id: int) -> Optional[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def get_upcoming_matches(self, league: str, days: int = 30) -> List[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def update_match_scores(self, match_id: int, home_score: int, away_score: int) -> bool:
        pass
    
    @abstractmethod
    def is_match_locked(self, match_id: int) -> bool:
        pass

# Prediction Interface
class IPredictionService(ABC):
    @abstractmethod
    def create_prediction(self, user_id: int, match_id: int, pick: Optional[str], margin: int) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def update_prediction(self, user_id: int, match_id: int, pick: Optional[str], margin: int) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def get_prediction(self, user_id: int, match_id: int) -> Optional[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def get_user_predictions(self, user_id: int) -> List[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def delete_prediction(self, user_id: int, match_id: int) -> bool:
        pass
    
    @abstractmethod
    def settle_predictions(self, match_id: int) -> bool:
        pass

# Group Interface
class IGroupService(ABC):
    @abstractmethod
    def create_group(self, name: str, owner_id: int, is_private: bool = True) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def get_group_by_id(self, group_id: int) -> Optional[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def join_group(self, user_id: int, invite_code: str) -> bool:
        pass
    
    @abstractmethod
    def leave_group(self, user_id: int, group_id: int) -> bool:
        pass
    
    @abstractmethod
    def transfer_ownership(self, current_owner_id: int, group_id: int, new_owner_id: int) -> bool:
        pass
    
    @abstractmethod
    def kick_member(self, owner_id: int, group_id: int, member_id: int) -> bool:
        pass

# Database Repository Interface
class IRepository(ABC):
    @abstractmethod
    def get_session(self) -> Session:
        pass
    
    @abstractmethod
    def close_session(self, session: Session) -> None:
        pass

# External API Interface
class IExternalAPIService(ABC):
    @abstractmethod
    def get_games_range(self, start_date: date, end_date: date, league: str) -> List[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def map_game_to_row(self, game: Dict[str, Any], league: str) -> Dict[str, Any]:
        pass 