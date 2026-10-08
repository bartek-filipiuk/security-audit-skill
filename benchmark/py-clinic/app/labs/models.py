from datetime import datetime, timezone

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(200), unique=True)
    full_name: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20))
    patient_id: Mapped[int | None] = mapped_column(nullable=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ApiSession(Base):
    __tablename__ = "api_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime]


class LabResult(Base):
    __tablename__ = "lab_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    patient_id: Mapped[int] = mapped_column(index=True)
    code: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    value: Mapped[str] = mapped_column(Text)
    pdf_path: Mapped[str] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(default=_now)


class LabOrder(Base):
    __tablename__ = "lab_orders"

    id: Mapped[int] = mapped_column(primary_key=True)
    patient_id: Mapped[int] = mapped_column(index=True)
    test_code: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="received")
    callback_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    callback_status: Mapped[int | None] = mapped_column(nullable=True)
    callback_response: Mapped[str | None] = mapped_column(Text, nullable=True)
