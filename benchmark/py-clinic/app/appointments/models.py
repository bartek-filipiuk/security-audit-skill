from django.conf import settings
from django.db import models


class Doctor(models.Model):
    name = models.CharField(max_length=120)
    specialty = models.CharField(max_length=80)
    bio = models.TextField(blank=True)


class Appointment(models.Model):
    STATUS_CHOICES = [("booked", "Booked"), ("done", "Done"), ("cancelled", "Cancelled")]

    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="appointments")
    doctor = models.ForeignKey(Doctor, on_delete=models.PROTECT)
    starts_at = models.DateTimeField()
    reason = models.CharField(max_length=200)
    notes = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="booked")
    paid = models.BooleanField(default=False)


class Message(models.Model):
    appointment = models.ForeignKey(Appointment, on_delete=models.CASCADE, related_name="messages")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


class Prescription(models.Model):
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="prescriptions")
    doctor = models.ForeignKey(Doctor, on_delete=models.PROTECT)
    drug = models.CharField(max_length=120)
    dosage = models.CharField(max_length=120)
    issued_at = models.DateTimeField(auto_now_add=True)


class ContactDetails(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="contact")
    email = models.EmailField()
    phone = models.CharField(max_length=32, blank=True)
