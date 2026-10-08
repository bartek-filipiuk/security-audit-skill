from rest_framework import serializers

from .models import Appointment, Doctor, Prescription


class DoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = ["id", "name", "specialty", "bio"]


class AppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = ["id", "doctor", "starts_at", "reason", "status"]
        read_only_fields = ["status"]


class PrescriptionSerializer(serializers.ModelSerializer):
    doctor = DoctorSerializer(read_only=True)

    class Meta:
        model = Prescription
        fields = ["id", "patient", "doctor", "drug", "dosage", "issued_at"]
