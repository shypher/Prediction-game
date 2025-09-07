from enum import Enum
from fastapi import status
import os
# HTTP Status Codes
class HTTPStatus:
    OK = status.HTTP_200_OK
    CREATED = status.HTTP_201_CREATED
    BAD_REQUEST = status.HTTP_400_BAD_REQUEST
    UNAUTHORIZED = status.HTTP_401_UNAUTHORIZED
    FORBIDDEN = status.HTTP_403_FORBIDDEN
    NOT_FOUND = status.HTTP_404_NOT_FOUND
    CONFLICT = status.HTTP_409_CONFLICT
    UNPROCESSABLE_ENTITY = status.HTTP_422_UNPROCESSABLE_ENTITY
    PRECONDITION_FAILED = status.HTTP_412_PRECONDITION_FAILED

# Error Messages
class ErrorMessages:
    NOT_AUTHENTICATED = "Not authenticated"
    ADMIN_PRIVILEGES_REQUIRED = "Admin privileges required"
    MATCH_NOT_FOUND = "Match not found"
    PREDICTION_NOT_FOUND = "Prediction not found"
    GROUP_NOT_FOUND = "Group not found"
    INVALID_CREDENTIALS = "Invalid authentication credentials"
    COULD_NOT_VALIDATE_CREDENTIALS = "Could not validate credentials"
    INCORRECT_USERNAME_OR_PASSWORD = "Incorrect username or password"
    PREDICTIONS_LOCKED = "Predictions are locked for this match"
    PREDICTION_ALREADY_SETTLED = "Prediction already settled"
    MATCH_NOT_FINISHED = "Match not finished"
    MATCH_NOT_FINISHED_DRAW = "Match not finished (draw/invalid)"
    OWN_PREDICTIONS_ONLY = "You can only edit your own predictions"
    OWNER_ONLY = "Only owner"
    OWNER_CANNOT_LEAVE = "Owner cannot leave. Transfer ownership or delete the group."
    OWNER_CANNOT_KICK_HIMSELF = "Owner cannot kick himself"
    NEW_OWNER_MUST_BE_MEMBER = "New owner must be a member"
    NOT_A_MEMBER = "Not a member"
    INVITE_CODE_REQUIRED = "Invite code required"
    UNKNOWN_LEAGUE = "Unknown league"
    LEAGUE_MUST_BE_SPECIFIC = "league must be EuroLeague | EuroBasket | Israel Super League"

# League Constants
class LeagueConstants:
    NBA = "NBA"
    EUROLEAGUE = "EuroLeague"
    EUROBASKET = "EuroBasket"
    ISRAEL_SUPER_LEAGUE = "Israel Super League"
    ISRAEL = "Israel"
    ISRAELI_SUPER_LEAGUE = "Israeli Super League"

# League Resolver Configuration
LEAGUE_RESOLVER = {
    LeagueConstants.NBA: {"source": "balldontlie"},
    LeagueConstants.EUROLEAGUE: {"source": "apisports", "id": 120},
    LeagueConstants.EUROBASKET: {"source": "apisports", "id": 197},
    LeagueConstants.ISRAEL_SUPER_LEAGUE: {"source": "apisports", "id": 51},
    LeagueConstants.ISRAEL: {"source": "apisports", "id": 51},
    LeagueConstants.ISRAELI_SUPER_LEAGUE: {"source": "apisports", "id": 51},
}

# Application Constants
class AppConstants:
    LOCK_MINUTES = 1  # minutes before match start
    SLOW_SEC = 60
    DEFAULT_DAYS_RANGE = 30

# Pick Enum
class PickEnum(str, Enum):
    HOME = "home"
    AWAY = "away"

# Match Status Enum
class MatchStatus(str, Enum):
    SCHEDULED = "scheduled"
    LIVE = "live"
    FINISHED = "finished"
    CANCELLED = "cancelled"

# Group Role Enum
class GroupRole(str, Enum):
    OWNER = "owner"
    MEMBER = "member"
    ADMIN = "admin"

# Route Paths
class RoutePaths:
    AUTH = "/auth"
    PREDICTIONS = "/predictions"
    GAMES = "/games"
    GROUPS = "/groups"
    LEADERBOARD = "/leaderboard"
    ME = "/me"
    INTERNAL_JOBS = "/internal-jobs"
    WEBSOCKET = "/ws" 
    
class League(str, Enum):
    NBA = "NBA"
    EUROLEAGUE = "EuroLeague"
    EUROBASKET = "EuroBasket"
    ISRAEL = "Israel Super League"

class ErrorMessages:
    UNKNOWN_LEAGUE = "Unknown league"
    
class BotID(int, Enum):
    CROWD_MEDIAN = os.getenv("BOT_CROWD_MEDIAN")
    CROWD_MEAN = os.getenv("BOT_CROWD_MEAN")
    BOOK_THEODDS = os.getenv("BOT_THEODDS")
    RANDOM_01 = os.getenv("BOT_ID_R1")
    RANDOM_02 = os.getenv("BOT_ID_R2")
    RANDOM_03 = os.getenv("BOT_ID_R3")
    
    
class BotDefaults:
    RANDOM_HOME_PROB = 0.60
    RANDOM_MARGIN_CENTER = 7.0
    RANDOM_MARGIN_SPREAD = 3.0
    RANDOM_MARGIN_MIN = 1
    RANDOM_MARGIN_MAX = 20
    RANDOM_DISTRIBUTION = "triangular"
    CROWD_OFFSET_MINUTES = 0
    CROWD_OVERWRITE = True