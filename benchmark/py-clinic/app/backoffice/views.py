import functools
import os

import yaml
from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    send_from_directory,
    url_for,
)
from flask_login import current_user, login_required, login_user
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from .models import PriceItem, StaffUser, db

bp = Blueprint("views", __name__)


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = StaffUser.query.filter_by(email=request.form["email"]).first()
        if user and check_password_hash(user.password_hash, request.form["password"]):
            login_user(user)
            return redirect(url_for("views.staff_list"))
    return render_template("login.html")


@bp.route("/staff")
@login_required
@admin_required
def staff_list():
    return render_template("staff.html", staff=StaffUser.query.order_by(StaffUser.full_name).all())


@bp.route("/staff/<int:user_id>/role", methods=["POST"])
def set_role(user_id):
    user = db.get_or_404(StaffUser, user_id)
    user.role = request.form["role"]
    db.session.commit()
    return redirect(url_for("views.staff_list"))


@bp.route("/letters/preview", methods=["POST"])
@login_required
def letter_preview():
    template = '<article class="letter"><h1>{{ clinic }}</h1>' + request.form.get("body", "") + "</article>"
    return render_template_string(template, clinic="Clinic")


@bp.route("/letters/send", methods=["POST"])
@login_required
def letter_send():
    return render_template("letter.html", body=request.form.get("body", ""), recipient=request.form.get("recipient", ""))


@bp.route("/exports/download")
@login_required
def download_export():
    name = request.args.get("name", "")
    return send_file(os.path.join(current_app.config["EXPORT_DIR"], name), as_attachment=True)


@bp.route("/reports/<name>")
@login_required
def report(name):
    return send_from_directory(current_app.config["REPORT_DIR"], secure_filename(name), as_attachment=True)


@bp.route("/prices/import", methods=["POST"])
@login_required
@admin_required
def import_prices():
    items = yaml.safe_load(request.files["file"].read()) or []
    for item in items:
        db.session.merge(PriceItem(code=item["code"], label=item["label"], amount_cents=int(item["amount_cents"])))
    db.session.commit()
    return redirect(url_for("views.staff_list"))
