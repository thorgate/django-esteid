import importlib
import re

import pytest


@pytest.mark.parametrize(
    "phone_number_regexp,compiled,result",
    [
        pytest.param(None, re.compile(r"^\+37[02]\d{7,8}$"), True, id="Not set"),
        pytest.param("", "", True, id="Empty string"),
        pytest.param(r"^xxx$", re.compile(r"^xxx$"), False, id="Arbitrary regexp"),
    ],
)
def test_mobile_id_phone_number_regexp(
    override_esteid_settings, phone_number_regexp, compiled, result, MID_DEMO_PIN_EE_OK, MID_DEMO_PHONE_EE_OK
):
    import esteid.mobileid.types

    with override_esteid_settings(MOBILE_ID_PHONE_NUMBER_REGEXP=phone_number_regexp):
        import esteid.settings

        assert esteid.settings.MOBILE_ID_PHONE_NUMBER_REGEXP == compiled

        importlib.reload(esteid.mobileid.types)
        ui = esteid.mobileid.types.UserInput(id_code=MID_DEMO_PIN_EE_OK, phone_number=MID_DEMO_PHONE_EE_OK)
        assert ui.is_valid(raise_exception=False) == result

    # Restore the module as it was before override
    importlib.reload(esteid.mobileid.types)


@pytest.mark.parametrize(
    "phone_number_regexp, phone, result",
    [
        pytest.param(None, "+18005551234", False, id="Not set"),
        pytest.param("", "+18005551234", True, id="Empty string"),
        pytest.param(r"^xxx$", "+18005551234", False, id="Arbitrary regexp not matching"),
        pytest.param(r"^\+1800\d+$", "+18005551234", True, id="Arbitrary regexp matching"),
    ],
)
def test_mobile_id_phone_number_regexp__error(
    override_esteid_settings,
    phone_number_regexp,
    phone,
    result,
    MID_DEMO_PIN_EE_OK,
):
    import esteid.mobileid.types

    with override_esteid_settings(MOBILE_ID_PHONE_NUMBER_REGEXP=phone_number_regexp):
        importlib.reload(esteid.mobileid.types)
        ui = esteid.mobileid.types.UserInput(id_code=MID_DEMO_PIN_EE_OK, phone_number=phone)
        assert ui.is_valid(raise_exception=False) == result

    # Restore the module as it was before override
    importlib.reload(esteid.mobileid.types)
