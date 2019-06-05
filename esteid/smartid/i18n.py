from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import ugettext_lazy as _

from .base import SmartIDService
from .constants import END_RESULT_DOCUMENT_UNUSABLE, END_RESULT_OK, END_RESULT_TIMEOUT, END_RESULT_USER_REFUSED


class TranslatedSmartIDService(SmartIDService):
    """SmartIDService w/ translatable error messages
    """
    MESSAGES = {
        'display_text': _('Log in with Smart-ID'),
        'permission_denied': _('No permission to issue the request'),
        'permission_denied_advanced': _('No permission to issue the request (set certificate_level to {})'),
        'no_identity_code': _('Identity {} was not found in Smart-ID system'),
        'no_session_code': _('Session {} does not exist'),
        'action_not_completed': _('Action for session {} has not completed yet'),
        'unexpected_state': _('Unexpected state {}'),
        'unexpected_end_result': _('Unexpected end result {}'),
        'signature_mismatch': _('Signature mismatch'),
        'timed_out': _('Connection timed out, retry later'),
        'invalid_credentials': _('Authentication failed: Check rp_uuid and verify the ip of the '
                                 'server has been added to the service contract'),
        'unsupported_client': _('The client is not supported'),
        'maintenance': _('System is under maintenance, retry later'),
        'proxy_error': _('Proxy error {}, retry later'),
        'http_error': _('Invalid response code(status_code: {0}, body: {1})'),
        'invalid_signature_algorithm': _('Invalid signature algorithm {}'),
    }

    END_RESULT_MESSAGES = {
        END_RESULT_OK: _('Successfully authenticated with Smart-ID'),
        END_RESULT_USER_REFUSED: _('User refused the Smart-ID request'),
        END_RESULT_TIMEOUT: _('Smart-ID request timed out'),
        END_RESULT_DOCUMENT_UNUSABLE: _('Smart-ID document is not usable. Please check your Smart-ID application '
                                        'or contact Smart-ID support'),
    }

    def msg(self, code):
        # Cast to string so translations are resolved
        return str(super(TranslatedSmartIDService, self).msg(code))

    def end_result_msg(self, end_result):
        # Cast to string so translations are resolved
        return str(super(TranslatedSmartIDService, self).end_result_msg(end_result))

    @classmethod
    def get_instance(cls):
        cls.configuration_valid()

        # NOTE: Test mode ON by default. To prevent accidental billing
        test_mode = getattr(settings, 'SMART_ID_TEST_MODE', True)
        api_root = getattr(settings, 'SMART_ID_API_ROOT',
                           TranslatedSmartIDService.TEST_API_ROOT if test_mode else TranslatedSmartIDService.API_ROOT)

        return TranslatedSmartIDService(
            rp_uuid=settings.SMART_ID_SERVICE_UUID,
            rp_name=settings.SMART_ID_SERVICE_NAME,
            api_root=api_root,
        )

    @staticmethod
    def configuration_valid():
        """Check if the required Smart-ID configuration parameters are set
        """
        keys = [
            'SMART_ID_SERVICE_NAME',
            'SMART_ID_SERVICE_UUID',
        ]

        if not all(getattr(settings, k, False) for k in keys):
            raise ImproperlyConfigured('One of the following settings is missing: {}'.format(
                ','.join(keys)
            ))
