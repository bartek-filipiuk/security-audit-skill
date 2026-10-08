from rest_framework import permissions, viewsets

from .models import Appointment, Doctor, Prescription
from .serializers import AppointmentSerializer, DoctorSerializer, PrescriptionSerializer


class AppointmentViewSet(viewsets.ModelViewSet):
    serializer_class = AppointmentSerializer

    def get_queryset(self):
        return Appointment.objects.filter(patient=self.request.user).select_related("doctor")

    def perform_create(self, serializer):
        serializer.save(patient=self.request.user)


class DoctorViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Doctor.objects.all().order_by("name")
    serializer_class = DoctorSerializer
    permission_classes = [permissions.AllowAny]


class PrescriptionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Prescription.objects.select_related("doctor").order_by("-issued_at")
    serializer_class = PrescriptionSerializer
