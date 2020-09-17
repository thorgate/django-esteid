from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import ugettext_lazy as _

from esteid.constants import MOBILE_ID_DEMO_URL, MOBILE_ID_LIVE_URL

from .base import MobileIDService
from .constants import EndResults


class TranslatedMobileIDService(MobileIDService):
    """MobileIDService w/ translatable error messages"""

    MESSAGES = {
        "display_text": _("Mobile-ID login"),  # NOTE:!!!! 20-char limit !!!!!!
        "permission_denied": _("No permission to issue the request"),
        "permission_denied_advanced": _("No permission to issue the request (set certificate_level to {})"),
        "no_identity_code": _("Identity {} was not found in Mobile-ID system"),
        "no_session_code": _("Session {} does not exist"),
        "action_not_completed": _("Action for session {} has not completed yet"),
        "unexpected_state": _("Unexpected state {}"),
        "unexpected_end_result": _("Unexpected end result {}"),
        "signature_mismatch": _("Signature mismatch"),
        "timed_out": _("Connection timed out, retry later"),
        "invalid_credentials": _(
            "Authentication failed: Check rp_uuid and verify the ip of the "
            "server has been added to the service contract"
        ),
        "unsupported_client": _("The client is not supported"),
        "maintenance": _("System is under maintenance, retry later"),
        "proxy_error": _("Proxy error {}, retry later"),
        "http_error": _("Invalid response code(status_code: {0}, body: {1})"),
        "invalid_signature_algorithm": _("Invalid signature algorithm {}"),
    }

    END_RESULT_MESSAGES = {
        EndResults.OK: _("Successfully authenticated with Mobile-ID"),
        EndResults.USER_CANCELLED: _("User canceled the Mobile-ID request"),
        EndResults.TIMEOUT: _("Mobile-ID request timed out"),
        EndResults.NOT_MID_CLIENT: _("User is not a Mobile-ID client."),
    }

    def msg(self, code):
        # Cast to string so translations are resolved
        return str(super().msg(code))

    def end_result_msg(self, end_result):
        # Cast to string so translations are resolved
        return str(super().end_result_msg(end_result))

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
