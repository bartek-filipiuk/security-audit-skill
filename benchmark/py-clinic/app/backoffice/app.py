import os

from flask import Flask
from flask_login import LoginManager

from .models import StaffUser, db

app = Flask(__name__)
app.secret_key = "backoffice-session-key"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("BACKOFFICE_DATABASE_URL", "sqlite:///backoffice.db")
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG") == "1"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["EXPORT_DIR"] = os.environ.get("BACKOFFICE_EXPORT_DIR", "/srv/backoffice/exports")
app.config["REPORT_DIR"] = os.environ.get("BACKOFFICE_REPORT_DIR", "/srv/backoffice/reports")

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "views.login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(StaffUser, int(user_id))


from .views import bp  # noqa: E402

app.register_blueprint(bp, url_prefix="/backoffice")
