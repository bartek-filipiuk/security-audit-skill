from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_staff
from ..db import get_db
from ..models import Account
from ..schemas import AccountPublic, AccountRecord

router = APIRouter(prefix="/staff", tags=["staff"], dependencies=[Depends(require_staff)])


@router.get("/me", response_model=AccountPublic)
def me(user: Account = Depends(require_staff)):
    return user


@router.get("/technicians", response_model=list[AccountRecord])
def technicians(db: Session = Depends(get_db)):
    return db.scalars(select(Account).where(Account.role == "technician").order_by(Account.full_name)).all()
