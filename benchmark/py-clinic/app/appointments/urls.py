from django.urls import path

from . import views

app_name = "appointments"

urlpatterns = [
    path("", views.appointment_list, name="list"),
    path("upcoming/", views.upcoming, name="upcoming"),
    path("search/", views.search, name="search"),
    path("<int:pk>/", views.appointment_detail, name="detail"),
    path("<int:pk>/messages/", views.post_message, name="post_message"),
    path("contact/", views.update_contact, name="contact"),
]
