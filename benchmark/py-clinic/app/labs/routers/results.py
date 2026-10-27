import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..db import get_db
from ..models import Account, LabResult
from ..schemas import LabResultOut

router = APIRouter(prefix="/results", tags=["results"])
RESULTS_DIR = os.environ.get("LABS_RESULTS_DIR", "/srv/labs/results")


@router.get("", response_model=list[LabResultOut])
def list_results(user: Account = Depends(get_current_user), db: Session = Depends(get_db)):
    query = select(LabResult).where(LabResult.patient_id == user.patient_id).order_by(LabResult.created_at.desc())
    return db.scalars(query).all()


@router.get("/search", response_model=list[LabResultOut])
def search_results(q: str, user: Account = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.execute(
        text(f"SELECT * FROM lab_results WHERE patient_id = :pid AND title ILIKE '%{q}%' ORDER BY created_at DESC"),
        {"pid": user.patient_id},
    )
    return [LabResultOut.model_validate(row._mapping) for row in rows]


@router.get("/by-code/{code}", response_model=list[LabResultOut])
def results_by_code(code: str, user: Account = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.execute(
        text("SELECT * FROM lab_results WHERE patient_id = :pid AND code = :code ORDER BY created_at DESC"),
        {"pid": user.patient_id, "code": code},
    )
    return [LabResultOut.model_validate(row._mapping) for row in rows]


@router.get("/{result_id}", response_model=LabResultOut)
def get_result(result_id: int, user: Account = Depends(get_current_user), db: Session = Depends(get_db)):
    result = db.scalar(select(LabResult).where(LabResult.id == result_id, LabResult.patient_id == user.patient_id))
    if result is None:
        raise HTTPException(status_code=404)
    return result


@router.get("/{result_id}/pdf")
def result_pdf(result_id: int, db: Session = Depends(get_db)):
    result = db.get(LabResult, result_id)
    if result is None:
        raise HTTPException(status_code=404)
    return FileResponse(os.path.join(RESULTS_DIR, result.pdf_path), media_type="application/pdf")
