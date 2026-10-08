import hashlib
import hmac
import json

from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from appointments.models import Appointment


@csrf_exempt
@require_POST
def payment_webhook(request):
    secret = settings.PAYMENT_WEBHOOK_SECRET.encode()
    if not secret:
        return HttpResponse(status=503)
    expected = hmac.new(secret, request.body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(request.headers.get("X-Signature", ""), expected):
        return HttpResponseBadRequest("signature mismatch")
    event = json.loads(request.body)
    if event.get("type") == "payment.succeeded":
        Appointment.objects.filter(pk=event["appointment_id"]).update(paid=True)
    return HttpResponse(status=204)
