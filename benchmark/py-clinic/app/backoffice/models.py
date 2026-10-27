from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class StaffUser(UserMixin, db.Model):
    __tablename__ = "staff_users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="clerk")
    password_hash = db.Column(db.String(200), nullable=False)


class PriceItem(db.Model):
    __tablename__ = "price_items"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    label = db.Column(db.String(200), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
