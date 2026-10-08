import httpx
from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..db import SessionLocal, get_db
from ..models import Account, LabOrder
from ..schemas import LabOrderIn, LabOrderOut

router = APIRouter(prefix="/orders", tags=["orders"])


def notify_callback(url: str, order_id: int) -> None:
    with SessionLocal() as db:
        order = db.get(LabOrder, order_id)
        response = httpx.post(url, json={"id": order.id, "status": order.status}, timeout=10)
        order.callback_status = response.status_code
        order.callback_response = response.text[:2000]
        db.commit()


@router.get("", response_model=list[LabOrderOut])
def list_orders(user: Account = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(select(LabOrder).where(LabOrder.patient_id == user.patient_id)).all()


@router.post("", response_model=LabOrderOut, status_code=201)
def create_order(
    body: LabOrderIn,
    background: BackgroundTasks,
    user: Account = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    order = LabOrder(patient_id=user.patient_id, test_code=body.test_code, callback_url=str(body.callback_url or ""))
    db.add(order)
    db.commit()
    db.refresh(order)
    if body.callback_url:
        background.add_task(notify_callback, str(body.callback_url), order.id)
    return order
