import csv
import io
import os

import yaml
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .models import HistoryEntry, Record


@login_required
def record_list(request):
    records = Record.objects.filter(owner=request.user).order_by("-uploaded_at")
    return render(request, "records/list.html", {"records": records})


@login_required
@require_POST
def upload(request):
    upload = request.FILES["file"]
    name = request.POST.get("filename") or upload.name
    target = os.path.join(settings.RECORDS_ROOT, str(request.user.id), name)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as out:
        for chunk in upload.chunks():
            out.write(chunk)
    Record.objects.create(owner=request.user, title=request.POST.get("title", name), path=target)
    return redirect("records:list")


@login_required
def download(request, record_id):
    record = get_object_or_404(Record, pk=record_id, owner=request.user)
    return FileResponse(open(record.path, "rb"), as_attachment=True, filename=os.path.basename(record.path))


@login_required
@require_POST
def import_history(request):
    data = yaml.load(request.FILES["file"].read(), Loader=yaml.Loader)
    for item in data.get("entries", []):
        HistoryEntry.objects.create(owner=request.user, kind=item["kind"], note=item.get("note", ""))
    return redirect("records:list")


def export_patients(request):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "name", "email", "phone"])
    for user in get_user_model().objects.filter(is_staff=False).select_related("contact"):
        contact = getattr(user, "contact", None)
        writer.writerow([user.id, user.get_full_name(), contact.email if contact else user.email, contact.phone if contact else ""])
    response = HttpResponse(buffer.getvalue(), content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="patients.csv"'
    return response
