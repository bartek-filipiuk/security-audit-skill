from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import Appointment, ContactDetails, Message


@login_required
def appointment_list(request):
    appointments = Appointment.objects.filter(patient=request.user).select_related("doctor").order_by("-starts_at")
    return render(request, "appointments/list.html", {"appointments": appointments})


@login_required
def upcoming(request):
    appointments = Appointment.objects.raw(
        "SELECT * FROM appointments_appointment WHERE patient_id = %s AND starts_at >= now() ORDER BY starts_at",
        [request.user.id],
    )
    return render(request, "appointments/list.html", {"appointments": appointments})


@login_required
def search(request):
    term = request.GET.get("q", "")
    appointments = Appointment.objects.raw(
        f"SELECT * FROM appointments_appointment WHERE patient_id = {request.user.id} AND reason ILIKE '%{term}%'"
    )
    return render(request, "appointments/list.html", {"appointments": appointments, "q": term})


@login_required
def appointment_detail(request, pk):
    appointment = get_object_or_404(Appointment.objects.select_related("doctor"), pk=pk)
    thread = appointment.messages.select_related("author").order_by("created_at")
    return render(request, "appointments/detail.html", {"appointment": appointment, "thread": thread})


@login_required
@require_POST
def post_message(request, pk):
    appointment = get_object_or_404(Appointment, pk=pk, patient=request.user)
    Message.objects.create(appointment=appointment, author=request.user, body=request.POST["body"])
    return redirect("appointments:detail", pk=pk)


@csrf_exempt
@login_required
@require_POST
def update_contact(request):
    contact, _ = ContactDetails.objects.get_or_create(user=request.user)
    contact.email = request.POST.get("email", contact.email)
    contact.phone = request.POST.get("phone", contact.phone)
    contact.save()
    request.user.email = contact.email
    request.user.save(update_fields=["email"])
    return JsonResponse({"email": contact.email, "phone": contact.phone})
