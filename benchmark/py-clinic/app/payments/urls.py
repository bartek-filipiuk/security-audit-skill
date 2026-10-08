from django.urls import path

from . import views

app_name = "payments"

urlpatterns = [
    path("webhook/", views.payment_webhook, name="webhook"),
]
