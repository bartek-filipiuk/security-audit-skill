import hashlib
from datetime import datetime, timezone

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import Account, ApiSession


def get_current_user(lab_session: str | None = Cookie(default=None), db: Session = Depends(get_db)) -> Account:
    if not lab_session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)
    token_hash = hashlib.sha256(lab_session.encode()).hexdigest()
    session = db.scalar(select(ApiSession).where(ApiSession.token_hash == token_hash))
    if session is None or session.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)
    return db.get(Account, session.account_id)


def require_staff(user: Account = Depends(get_current_user)) -> Account:
    if user.role != "technician":
        raise HTTPException(status.HTTP_403_FORBIDDEN)
    return user
