from fastapi import APIRouter, Depends, HTTPException, Query, Header
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional, List
import secrets

from ..db import models, schemas
from .auth import get_current_user
from ..core import database
from ..core.constants import HTTPStatus, ErrorMessages
from ..db.schemas import MyGroupOut


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
        raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.GROUP_NOT_FOUND)

    if g.is_private and g.invite_code != invite_code and user_id != g.owner_id:
        raise HTTPException(HTTPStatus.FORBIDDEN, ErrorMessages.INVITE_CODE_REQUIRED)

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
        raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.GROUP_NOT_FOUND)
    if g.owner_id == user_id:
        raise HTTPException(HTTPStatus.CONFLICT, ErrorMessages.OWNER_CANNOT_LEAVE)

    r = db.query(models.GroupMember).filter_by(group_id=group_id, user_id=user_id).delete()
    if r == 0:
        raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.NOT_A_MEMBER)
    db.commit()
    return {"ok": True}

@router.post("/{group_id}/regen-invite")
def regen_invite(group_id: int, db: Session = Depends(get_db), me: dict = Depends(get_current_user)):
    user_id = me["id"]
    g = db.get(models.Group, group_id)
    if not g: raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.GROUP_NOT_FOUND)
    if g.owner_id != user_id: raise HTTPException(HTTPStatus.FORBIDDEN, ErrorMessages.OWNER_ONLY)
    g.invite_code = _new_invite_code()
    db.commit()
    return {"invite_code": g.invite_code}

@router.post("/{group_id}/transfer-ownership/{new_owner_id}")
def transfer_owner(group_id: int, new_owner_id: str, db: Session = Depends(get_db), me: dict = Depends(get_current_user)):
    user_id = me["id"]
    g = db.get(models.Group, group_id)
    if not g: raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.GROUP_NOT_FOUND)
    if g.owner_id != user_id: raise HTTPException(HTTPStatus.FORBIDDEN, ErrorMessages.OWNER_ONLY)
    mem = db.query(models.GroupMember).filter_by(group_id=group_id, user_id=new_owner_id).first()
    if not mem: raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.NEW_OWNER_MUST_BE_MEMBER)
    g.owner_id = new_owner_id
    db.commit()
    return {"ok": True}

@router.delete("/{group_id}/kick/{member_id}")
def kick_member(group_id: int, member_id: str, db: Session = Depends(get_db), me: dict = Depends(get_current_user)):
    user_id = me["id"]
    g = db.get(models.Group, group_id)
    if not g: raise HTTPException(HTTPStatus.NOT_FOUND, ErrorMessages.GROUP_NOT_FOUND)
    if g.owner_id != user_id: raise HTTPException(HTTPStatus.FORBIDDEN, ErrorMessages.OWNER_ONLY)
    if member_id == user_id: raise HTTPException(HTTPStatus.BAD_REQUEST, ErrorMessages.OWNER_CANNOT_KICK_HIMSELF)
    db.query(models.GroupMember).filter_by(group_id=group_id, user_id=member_id).delete()
    db.commit()
    return {"ok": True}

@router.get("/my", response_model=List[MyGroupOut], summary="הקבוצות של המשתמש המחובר")
def my_groups(
    include_owned: bool = Query(True, description="להחזיר גם קבוצות שהמשתמש בעליהן"),
    include_member: bool = Query(True, description="להחזיר גם קבוצות שהמשתמש חבר בהן"),
    db: Session = Depends(get_db),
    me: dict = Depends(get_current_user),
):
    if not include_owned and not include_member:
        return []

    uid = me["id"]

    results: dict[int, MyGroupOut] = {}

    if include_owned:
        owned = db.query(models.Group).filter(models.Group.owner_id == uid).all()
        for g in owned:
            results[g.id] = MyGroupOut(
                id=g.id,
                name=g.name,
                role="owner",
                owner_id=g.owner_id,
                is_private=bool(g.is_private),
                invite_code=getattr(g, "invite_code", None),
                created_at=getattr(g, "created_at", None),
            )

    if include_member:
        rows = (
            db.query(models.Group, models.GroupMember.role)
              .join(models.GroupMember, models.GroupMember.group_id == models.Group.id)
              .filter(models.GroupMember.user_id == uid)
              .all()
        )
        for g, role in rows:
            if g.id in results and results[g.id].role == "owner":
                continue
            results[g.id] = MyGroupOut(
                id=g.id,
                name=g.name,
                role=role or "member",
                owner_id=g.owner_id,
                is_private=bool(g.is_private),
                invite_code=getattr(g, "invite_code", None),
                created_at=getattr(g, "created_at", None),
            )

    out = list(results.values())
    out.sort(key=lambda x: (x.name or "").lower())
    return out