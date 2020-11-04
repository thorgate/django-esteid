from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import ugettext_lazy as _

from ..constants import SMART_ID_DEMO_URL, SMART_ID_LIVE_URL
from .base import SmartIDService


class TranslatedSmartIDService(SmartIDService):
    """SmartIDService w/ translatable error messages"""

    DISPLAY_TEXT_AUTH = _("Authenticate")
    DISPLAY_TEXT_SIGN = _("Sign")

    @classmethod
    def get_instance(cls):
        cls.configuration_valid()

        # NOTE: Test mode ON by default. To prevent accidental billing
        test_mode = getattr(settings, "SMART_ID_TEST_MODE", True)
        api_root = getattr(
            settings,
            "SMART_ID_API_ROOT",
            SMART_ID_DEMO_URL if test_mode else SMART_ID_LIVE_URL,
        )

        return TranslatedSmartIDService(
            rp_uuid=settings.SMART_ID_SERVICE_UUID,
            rp_name=settings.SMART_ID_SERVICE_NAME,
            api_root=api_root,
        )

    @staticmethod
    def configuration_valid():
        """Check if the required Smart-ID configuration parameters are set"""
        keys = [
            "SMART_ID_SERVICE_NAME",
            "SMART_ID_SERVICE_UUID",
        ]

        if not all(getattr(settings, k, False) for k in keys):
            raise ImproperlyConfigured("One of the following settings is missing: {}".format(",".join(keys)))
