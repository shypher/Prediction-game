from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from . import models, schemas, auth, database, getGames
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from .auth import get_current_user
import os
import requests
from .utils.migrations import ensure_match_columns

models.Base.metadata.create_all(bind=database.engine)
ensure_match_columns(database.engine)

app = FastAPI()
app.include_router(auth.router)
app.include_router(getGames.router)

# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]        
@app.get("/",status_code=status.HTTP_200_OK)
async def user(user:user_dependency, db:db_dependency):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return {"User": user}


# def home():
#     return {"message": "Fantasy API running! dash leShimi"}

# @app.post("/register", response_model=schemas.UserResponse)
# def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
#     # Check if email already exists
#     if db.query(models.User).filter(models.User.email == user.email).first():
#         raise HTTPException(status_code=400, detail="Email already registered")
#     if db.query(models.User).filter(models.User.username == user.username).first():
#         raise HTTPException(status_code=400, detail="Username already taken")

#     hashed_pw = auth.hash_password(user.password)
#     new_user = models.User(username=user.username, email=user.email, hashed_password=hashed_pw)
#     db.add(new_user)
#     db.commit()
#     db.refresh(new_user)
#     return new_user

# @app.post("/login", response_model=schemas.Token)
# def login(user_data: schemas.UserLogin, db: Session = Depends(get_db)):
#     user = db.query(models.User).filter(models.User.email == user_data.email).first()
#     if not user or not auth.verify_password(user_data.password, user.hashed_password):
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

#     access_token = auth.create_access_token(data={"sub": user.email})
#     return {"access_token": access_token, "token_type": "bearer"}
# @app.get("/me", response_model=schemas.UserResponse)
# def read_me(current_user: models.User = Depends(get_current_user)):
#     return current_user
# @app.post("/logout")
# def logout():
#     # On JWT systems without a blacklist, logout is just deleting the token client-side.
#     return {"message": "Successfully logged out. Please delete your token on the client side."}