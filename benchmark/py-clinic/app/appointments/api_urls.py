from rest_framework.routers import DefaultRouter

from .api import AppointmentViewSet, DoctorViewSet, PrescriptionViewSet

router = DefaultRouter()
router.register(r"appointments", AppointmentViewSet, basename="appointment")
router.register(r"doctors", DoctorViewSet, basename="doctor")
router.register(r"prescriptions", PrescriptionViewSet, basename="prescription")

urlpatterns = router.urls
