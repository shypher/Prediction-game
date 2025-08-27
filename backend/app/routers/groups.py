from fastapi import APIRouter, Depends, HTTPException, Query, Header
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional, List
import secrets
from .auth import get_current_user
from app import database, models, schemas



router = APIRouter(prefix="/groups", tags=["groups"])



def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _new_invite_code() -> str:
    return secrets.token_urlsafe(6)

@router.post("", response_model=schemas.GroupOut)
def create_group(
    payload: schemas.GroupCreate,
    db: Session = Depends(get_db),
    me: dict = Depends(get_current_user),
):
    user_id = me["id"]
    invite = _new_invite_code() if payload.is_private else None
    g = models.Group(name=payload.name, owner_id=user_id, invite_code=invite, is_private=payload.is_private)
    db.add(g)
    db.flush()
    db.add(models.GroupMember(group_id=g.id, user_id=user_id, role="owner"))
    db.commit()
    # member_count
    cnt = db.query(func.count(models.GroupMember.user_id)).filter(models.GroupMember.group_id == g.id).scalar() or 0
    return schemas.GroupOut(id=g.id, name=g.name, owner_id=g.owner_id, invite_code=g.invite_code, is_private=g.is_private, member_count=cnt)

@router.post("/{group_id}/join", response_model=schemas.GroupOut)
def join_group(
    group_id: int,
    invite_code: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    me: dict = Depends(get_current_user),
):
    user_id = me["id"]
    g = db.get(models.Group, group_id)
    if not g:
        raise HTTPException(404, "Group not found")

    if g.is_private and g.invite_code != invite_code and user_id != g.owner_id:
        raise HTTPException(403, "Invite code required")

    exists = db.query(models.GroupMember).filter_by(group_id=group_id, user_id=user_id).first()
    if not exists:
        db.add(models.GroupMember(group_id=group_id, user_id=user_id, role="member"))
        db.commit()

    cnt = db.query(func.count(models.GroupMember.user_id)).filter(models.GroupMember.group_id == group_id).scalar() or 0
    return schemas.GroupOut(id=g.id, name=g.name, owner_id=g.owner_id, invite_code=g.invite_code, is_private=g.is_private, member_count=cnt)

@router.post("/{group_id}/leave")
def leave_group(
    group_id: int,
    db: Session = Depends(get_db),
    me: dict = Depends(get_current_user),
):
    user_id = me["id"]
    g = db.get(models.Group, group_id)
    if not g:
        raise HTTPException(404, "Group not found")
    if g.owner_id == user_id:
        raise HTTPException(409, "Owner cannot leave. Transfer ownership or delete the group.")

    r = db.query(models.GroupMember).filter_by(group_id=group_id, user_id=user_id).delete()
    if r == 0:
        raise HTTPException(404, "Not a member")
    db.commit()
    return {"ok": True}
