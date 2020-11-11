from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import ugettext_lazy as _

from esteid import settings

from .base import SmartIDService


class TranslatedSmartIDService(SmartIDService):
    """SmartIDService w/ translatable error messages"""

    DISPLAY_TEXT_AUTH = _("Authenticate")
    DISPLAY_TEXT_SIGN = _("Sign")

    @classmethod
    def get_instance(cls):
        cls.configuration_valid()

        return TranslatedSmartIDService(
            rp_uuid=settings.SMART_ID_SERVICE_UUID,
            rp_name=settings.SMART_ID_SERVICE_NAME,
            api_root=settings.SMART_ID_API_ROOT,
        )

    @staticmethod
    def configuration_valid():
        if not (settings.SMART_ID_SERVICE_NAME and settings.SMART_ID_SERVICE_UUID):
            raise ImproperlyConfigured("Both SMART_ID_SERVICE_NAME and SMART_ID_SERVICE_UUID must be set")
