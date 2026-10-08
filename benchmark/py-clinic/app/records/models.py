from django.conf import settings
from django.db import models


class Record(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="records")
    title = models.CharField(max_length=200)
    path = models.CharField(max_length=500)
    uploaded_at = models.DateTimeField(auto_now_add=True)


class HistoryEntry(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="history")
    kind = models.CharField(max_length=40)
    note = models.TextField(blank=True)
