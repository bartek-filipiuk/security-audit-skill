from datetime import datetime

from pydantic import BaseModel, ConfigDict, HttpUrl


class LabResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    code: str
    title: str
    value: str
    created_at: datetime


class LabOrderIn(BaseModel):
    test_code: str
    callback_url: HttpUrl | None = None


class LabOrderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    test_code: str
    status: str
    callback_status: int | None = None
    callback_response: str | None = None


class AccountPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    role: str


class AccountRecord(AccountPublic):
    patient_id: int | None = None
    password_hash: str
    totp_secret: str | None = None
