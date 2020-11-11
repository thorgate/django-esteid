from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import ugettext_lazy as _

from esteid import settings

from .base import MobileIDService


class TranslatedMobileIDService(MobileIDService):
    """MobileIDService w/ translatable messages and django settings-aware"""

    # NOTE:!!!! 20-char limit !!!!!!
    DISPLAY_TEXT_AUTH = _("Authenticate")
    DISPLAY_TEXT_SIGN = _("Sign")

    @classmethod
    def get_instance(cls) -> "TranslatedMobileIDService":
        cls.configuration_valid()

        return cls(
            rp_uuid=settings.MOBILE_ID_SERVICE_UUID,
            rp_name=settings.MOBILE_ID_SERVICE_NAME,
            api_root=settings.MOBILE_ID_API_ROOT,
        )

    @staticmethod
    def configuration_valid():
        if not (settings.MOBILE_ID_SERVICE_NAME and settings.MOBILE_ID_SERVICE_UUID):
            raise ImproperlyConfigured("Both MOBILE_ID_SERVICE_NAME and MOBILE_ID_SERVICE_UUID must be set")
