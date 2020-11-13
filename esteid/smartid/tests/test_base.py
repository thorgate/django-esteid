import pytest

import requests
import requests_mock
from django.core.exceptions import ImproperlyConfigured
from requests.exceptions import ConnectTimeout

from ...constants import SMART_ID_DEMO_URL, SMART_ID_LIVE_URL
from ...exceptions import (
    BadRequest,
    EsteidError,
    InvalidCredentials,
    OfflineError,
    UnsupportedClientImplementation,
    UpstreamServiceError,
)
from .. import SmartIDError
from ..base import SmartIDService
from ..i18n import TranslatedSmartIDService


def test_error():
    assert SmartIDError is EsteidError


@pytest.mark.parametrize("exc", [ConnectionError, requests.ConnectionError, ConnectTimeout])
def test_smartid_invoke_timeout(demo_api, exc):
    with requests_mock.mock() as m:
        m.get(demo_api.api_url(""), exc=exc)

        with pytest.raises(OfflineError):
            demo_api.invoke("")


@pytest.mark.parametrize(
    "status_code,exc",
    [
        (401, InvalidCredentials),
        (480, UnsupportedClientImplementation),
        (580, OfflineError),
        (502, OfflineError),
        (503, OfflineError),
        (504, OfflineError),
        (400, BadRequest),
        (500, UpstreamServiceError),
    ],
)
def test_smartid_invoke_errors(demo_api, status_code, exc):
    with requests_mock.mock() as m:
        m.get(demo_api.api_url(""), status_code=status_code)

        with pytest.raises(exc):
            demo_api.invoke("")


def test_smartid_service(demo_api):
    assert demo_api.api_root == SMART_ID_DEMO_URL

    service = SmartIDService("00000000-0000-0000-0000-000000000000", "test", SMART_ID_LIVE_URL)
    assert service.api_root == SMART_ID_LIVE_URL
    assert service.rp_uuid == "00000000-0000-0000-0000-000000000000"
    assert service.rp_name == "test"


def test_smartid_translated_service(i18n_demo_api):
    assert i18n_demo_api.api_root == SMART_ID_DEMO_URL


def test_smartid_translated_service_test_mode_off(override_esteid_settings):
    with override_esteid_settings(
        SMART_ID_TEST_MODE=False,
        SMART_ID_SERVICE_UUID="00000000-0000-0000-0000-000000000000",
        SMART_ID_SERVICE_NAME="test",
    ):
        service = TranslatedSmartIDService.get_instance()
        assert service.api_root == SMART_ID_LIVE_URL
        assert service.rp_uuid == "00000000-0000-0000-0000-000000000000"
        assert service.rp_name == "test"


def test_smartid_translated_service_requires_creds_for_live(override_esteid_settings):
    with override_esteid_settings(SMART_ID_TEST_MODE=False):
        with pytest.raises(ImproperlyConfigured, match="SMART_ID_SERVICE_NAME and SMART_ID_SERVICE_UUID"):
            TranslatedSmartIDService.get_instance()

    with override_esteid_settings(
        SMART_ID_TEST_MODE=False,
        SMART_ID_SERVICE_UUID="00000000-0000-0000-0000-000000000000",
    ):
        with pytest.raises(ImproperlyConfigured, match="SMART_ID_SERVICE_NAME and SMART_ID_SERVICE_UUID"):
            TranslatedSmartIDService.get_instance()

    with override_esteid_settings(SMART_ID_TEST_MODE=False, SMART_ID_SERVICE_NAME="name"):
        with pytest.raises(ImproperlyConfigured, match="SMART_ID_SERVICE_NAME and SMART_ID_SERVICE_UUID"):
            TranslatedSmartIDService.get_instance()
