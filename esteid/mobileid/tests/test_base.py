import pytest

import requests_mock
from django.core.exceptions import ImproperlyConfigured
from requests.exceptions import ConnectTimeout

from ...constants import MOBILE_ID_DEMO_URL, MOBILE_ID_LIVE_URL
from ...exceptions import EsteidError, InvalidCredentials, OfflineError, UpstreamServiceError
from .. import MobileIDError
from ..base import MobileIDService
from ..i18n import TranslatedMobileIDService


def test_error():
    assert MobileIDError is EsteidError


@pytest.mark.parametrize("exc", [ConnectionError, ConnectTimeout])
def test_mobileid_invoke_timeout(demo_mid_api, exc):
    with requests_mock.mock() as m:
        m.get(demo_mid_api.api_url(""), exc=exc)

        with pytest.raises(OfflineError) as exc_info:
            demo_mid_api.invoke("")

        assert demo_mid_api.NAME in exc_info.value.get_message()


@pytest.mark.parametrize(
    "status_code,exc",
    [
        (401, InvalidCredentials),
        (580, OfflineError),
        (502, OfflineError),
        (503, OfflineError),
        (504, OfflineError),
        (400, MobileIDError),
        (500, UpstreamServiceError),
    ],
)
def test_mobileid_invoke_errors(demo_mid_api, status_code, exc):
    with requests_mock.mock() as m:
        m.get(demo_mid_api.api_url(""), status_code=status_code)

        with pytest.raises(exc):
            demo_mid_api.invoke("")


def test_mobileid_service(demo_mid_api):
    assert demo_mid_api.api_root == MOBILE_ID_DEMO_URL

    service = MobileIDService("00000000-0000-0000-0000-000000000000", "test", MOBILE_ID_LIVE_URL)
    assert service.api_root == MOBILE_ID_LIVE_URL
    assert service.rp_uuid == "00000000-0000-0000-0000-000000000000"
    assert service.rp_name == "test"


def test_mobileid_translated_service(i18n_demo_mid_api):
    assert i18n_demo_mid_api.api_root == MOBILE_ID_DEMO_URL


def test_mobileid_translated_service_test_mode_off(i18n_demo_mid_api, override_esteid_settings):
    with override_esteid_settings(
        MOBILE_ID_TEST_MODE=False,
        MOBILE_ID_SERVICE_UUID="00000000-0000-0000-0000-000000000000",
        MOBILE_ID_SERVICE_NAME="test",
    ):
        service = TranslatedMobileIDService.get_instance()
        assert service.api_root == MOBILE_ID_LIVE_URL
        assert service.rp_uuid == "00000000-0000-0000-0000-000000000000"
        assert service.rp_name == "test"


def test_mobileid_translated_service_requires_creds_for_live(override_esteid_settings):
    with override_esteid_settings(MOBILE_ID_TEST_MODE=False):
        with pytest.raises(ImproperlyConfigured, match="MOBILE_ID_SERVICE_NAME and MOBILE_ID_SERVICE_UUID"):
            TranslatedMobileIDService.get_instance()

    with override_esteid_settings(
        MOBILE_ID_TEST_MODE=False,
        MOBILE_ID_SERVICE_UUID="00000000-0000-0000-0000-000000000000",
    ):
        with pytest.raises(ImproperlyConfigured, match="MOBILE_ID_SERVICE_NAME and MOBILE_ID_SERVICE_UUID"):
            TranslatedMobileIDService.get_instance()

    with override_esteid_settings(MOBILE_ID_TEST_MODE=False, MOBILE_ID_SERVICE_NAME="name"):
        with pytest.raises(ImproperlyConfigured, match="MOBILE_ID_SERVICE_NAME and MOBILE_ID_SERVICE_UUID"):
            TranslatedMobileIDService.get_instance()
