from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import os

from ..db.models import User
from ..interfaces import IUserService
from ..constants import HTTPStatus, ErrorMessages

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = os.getenv("ALGORITHM")

class UserService(IUserService):
    def __init__(self, db: Session):
        self.db = db
    
    def create_user(self, username: str, email: str, password: str) -> Dict[str, Any]:
        """Create a new user"""
        hashed_password = bcrypt_context.hash(password)
        user = User(
            username=username,
            email=email,
            hashed_password=hashed_password
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return {"id": user.id, "username": user.username, "email": user.email}
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with username and password"""
        user = self.db.query(User).filter(User.username == username).first()
        if not user:
            return None
        if not bcrypt_context.verify(password, user.hashed_password):
            return None
        return {"id": user.id, "username": user.username, "email": user.email}
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return None
        return {"id": user.id, "username": user.username, "email": user.email}
    
    def is_admin(self, user_id: int) -> bool:
        """Check if user is admin"""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        return user.is_admin
    
    def create_access_token(self, username: str, user_id: int, expires_delta: timedelta) -> str:
        """Create JWT access token"""
        encode = {'sub': username, 'id': user_id}
        expires = datetime.utcnow() + expires_delta
        encode.update({"exp": expires})
        return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return user info"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            user_id: int = payload.get("id")
            if username is None or user_id is None:
                return None
            return {"username": username, "id": user_id}
        except jwt.JWTError:
            return None 