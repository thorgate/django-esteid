from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import ugettext_lazy as _

from esteid.constants import MOBILE_ID_DEMO_URL, MOBILE_ID_LIVE_URL

from .base import MobileIDService


class TranslatedMobileIDService(MobileIDService):
    """MobileIDService w/ translatable messages and django settings-aware"""

    # NOTE:!!!! 20-char limit !!!!!!
    DISPLAY_TEXT_AUTH = _("Authenticate")
    DISPLAY_TEXT_SIGN = _("Sign")

    @classmethod
    def get_instance(cls) -> "TranslatedMobileIDService":
        cls.configuration_valid()

        # NOTE: Test mode ON by default. To prevent accidental billing
        test_mode = getattr(settings, "MOBILE_ID_TEST_MODE", True)
        api_root = getattr(settings, "MOBILE_ID_API_ROOT", MOBILE_ID_DEMO_URL if test_mode else MOBILE_ID_LIVE_URL)

        return cls(
            rp_uuid=settings.MOBILE_ID_SERVICE_UUID,
            rp_name=settings.MOBILE_ID_SERVICE_NAME,
            api_root=api_root,
        )

    @staticmethod
    def configuration_valid():
        """Check if the required Mobile-ID configuration parameters are set"""
        keys = [
            "MOBILE_ID_SERVICE_NAME",
            "MOBILE_ID_SERVICE_UUID",
        ]

        if not all(getattr(settings, k, False) for k in keys):
            raise ImproperlyConfigured("One of the following settings is missing: {}".format(",".join(keys)))
