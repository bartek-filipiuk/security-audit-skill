from django import template
from django.utils.html import format_html

register = template.Library()

STATUS_CLASSES = {"booked": "info", "done": "success", "cancelled": "muted"}


@register.simple_tag
def status_badge(appointment):
    css = STATUS_CLASSES.get(appointment.status, "muted")
    return format_html('<span class="badge badge-{}">{}</span>', css, appointment.get_status_display())
