from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/login/", auth_views.LoginView.as_view(), name="login"),
    path("accounts/password-reset/", auth_views.PasswordResetView.as_view(), name="password_reset"),
    path("appointments/", include("appointments.urls")),
    path("records/", include("records.urls")),
    path("payments/", include("payments.urls")),
    path("api/", include("appointments.api_urls")),
]
