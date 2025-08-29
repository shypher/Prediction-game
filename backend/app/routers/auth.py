from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, HTTPException, APIRouter
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status

from ..db import models
from ..db.models import User
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from ..database import SessionLocal
from authlib.integrations.starlette_client import OAuth
from starlette.responses import RedirectResponse
from dotenv import load_dotenv
from .. import database
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.database import get_user_by_email, create_user
import httpx
from ..constants import HTTPStatus, ErrorMessages
from ..services.user_service import UserService

# load_dotenv()
router = APIRouter( prefix="/auth", tags=["auth"])
# oauth = OAuth()
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = os.getenv("ALGORITHM")
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    
class Token(BaseModel):
    access_token: str
    token_type: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

@router.post("/", status_code=HTTPStatus.CREATED)
async def create_user(db:db_dependency,crate_user_request: UserCreate):
    user_service = UserService(db)
    user_service.create_user(
        username=crate_user_request.username,
        email=crate_user_request.email,
        password=crate_user_request.password
    )

@router.post("/token", response_model=Token)
async def login_for_access_token(from_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: db_dependency):
    user_service = UserService(db)
    user = user_service.authenticate_user(from_data.username, from_data.password)
    if not user:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail=ErrorMessages.INCORRECT_USERNAME_OR_PASSWORD)
    token = user_service.create_access_token(user["username"], user["id"], timedelta(minutes=30))
    return {"access_token": token, "token_type": "bearer"}
        

async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try: 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        if username is None or user_id is None:
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                detail=ErrorMessages.INVALID_CREDENTIALS)
        return {"username": username, "id": user_id}
    except JWTError:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail=ErrorMessages.COULD_NOT_VALIDATE_CREDENTIALS)
   
   
   
####       Google auth
# ACCESS_TOKEN_EXPIRE_MINUTES = 30
# GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
# GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")


# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# oauth.register(
#     name='google',
#     client_id=os.getenv("GOOGLE_CLIENT_ID"),
#     client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
#     server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
#     client_kwargs={'scope': 'openid email profile'}
# )


# @router.get("/auth/google")
# def login_with_google():
#     google_auth_url = (
#         "https://accounts.google.com/o/oauth2/v2/auth"
#         "?response_type=code"
#         f"&client_id={GOOGLE_CLIENT_ID}"
#         f"&redirect_uri={GOOGLE_REDIRECT_URI}"
#         "&scope=openid%20email%20profile"
#     )
#     return RedirectResponse(google_auth_url)


# @router.get("/auth/google/callback")
# async def google_callback(code: str):
#     # 1. Exchange code for access token
#     token_resp = httpx.post(
#         "https://oauth2.googleapis.com/token",
#         data={
#             "code": code,
#             "client_id": GOOGLE_CLIENT_ID,
#             "client_secret": GOOGLE_CLIENT_SECRET,
#             "redirect_uri": GOOGLE_REDIRECT_URI,
#             "grant_type": "authorization_code",
#         }
#     )
#     token_data = token_resp.json()
#     access_token = token_data.get("access_token")

#     if not access_token:
#         raise HTTPException(status_code=400, detail="Google authentication failed")

#     # 2. Get user info from Google
#     user_resp = httpx.get(
#         "https://www.googleapis.com/oauth2/v1/userinfo",
#         params={"alt": "json"},
#         headers={"Authorization": f"Bearer {access_token}"}
#     )
#     user_data = user_resp.json()

#     email = user_data.get("email")
#     name = user_data.get("name", "")
    
#     if not email:
#         raise HTTPException(status_code=400, detail="No email found from Google")

#     # 3. Check if user exists, otherwise create
#     user = get_user_by_email(email)
#     if not user:
#         user = create_user(username=name, email=email, password=None, provider="google")

#     # 4. Generate JWT token
#     jwt_token = create_access_token({"sub": email}, expires_delta=timedelta(hours=1))

#     # 5. Redirect with token or return JSON
#     return {"access_token": jwt_token, "token_type": "bearer"}

# def hash_password(password: str) -> str:
#     return pwd_context.hash(password)

# def verify_password(plain_password: str, hashed_password: str) -> bool:
#     return pwd_context.verify(plain_password, hashed_password)

# def create_access_token(data: dict, expires_delta: timedelta | None = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# def verify_token(token: str):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         return payload
#     except JWTError:
#         return None
    

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
# def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.SessionLocal)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         email: str = payload.get("sub")
#         if email is None:
#             raise credentials_exception
#     except JWTError:
#         raise credentials_exception
    
#     user = db.query(models.User).filter(models.User.email == email).first()
#     if user is None:
#         raise credentials_exception
#     return user