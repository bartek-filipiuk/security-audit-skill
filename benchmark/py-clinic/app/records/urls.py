from django.urls import path

from . import views

app_name = "records"

urlpatterns = [
    path("", views.record_list, name="list"),
    path("upload/", views.upload, name="upload"),
    path("<int:record_id>/download/", views.download, name="download"),
    path("import/", views.import_history, name="import"),
    path("export/patients.csv", views.export_patients, name="export_patients"),
]
