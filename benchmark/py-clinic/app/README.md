# Clinic

Patient portal of a small outpatient clinic, with a lab results service and a
staff back office.

## Layout

- `/` (Django 5): the patient portal. Patients book appointments, message
  their doctor, upload medical records and see prescriptions. Pages in
  `appointments/` and `records/`, the JSON API for the mobile app in
  `appointments/api.py` (Django REST framework, session auth), the payment
  provider's webhook in `payments/`.
- `labs/` (FastAPI): lab results and lab orders. Patients and partner clinics
  sign in with the `lab_session` cookie; technicians use the `/staff` routes.
- `backoffice/` (Flask): the staff back office, with letters, exports,
  reports and the price list.

## Running locally

    python -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env
    python manage.py migrate
    python manage.py runserver

    pip install -r labs/requirements.txt
    uvicorn labs.main:app --reload --port 8001

    pip install -r backoffice/requirements.txt
    flask --app backoffice.app run --port 8002

## Security

- Every portal page requires a signed-in patient; patients only see their own
  appointments, records and prescriptions.
- Password reset links are sent to the contact e-mail of the account.
- The API uses Django sessions; staff use the Django admin.
- Payment webhooks are signed (HMAC-SHA256).
- Lab results are visible to their patient only; `/staff` is for technicians.
- The back office is for staff only; role changes and the price list are for
  admins.
