import pytest

from django.core.exceptions import ImproperlyConfigured

from esteid.constants import Languages


@pytest.mark.parametrize(
    "lang_code, result",
    [
        *[(code.upper(), code) for code in Languages.ALL],
        *[(code.lower(), code) for code in Languages.ALL],
        *[(alpha2.upper(), code) for alpha2, code in Languages._MAP_ISO_639_1_TO_MID.items()],
        *[(alpha2.lower(), code) for alpha2, code in Languages._MAP_ISO_639_1_TO_MID.items()],
        # These tests duplicate the ones above, just for clarity here.
        ("et", "EST"),
        ("est", "EST"),
        ("ET", "EST"),
        ("EST", "EST"),
        (None, ImproperlyConfigured("Language should be one of .+, got `None`")),
        ("whatever", ImproperlyConfigured("Language should be one of .+, got `whatever`")),
        (object, ImproperlyConfigured("Language should be one of .+, got `<class 'object'>`")),
    ],
)
def test_languages_identify_language(lang_code, result):
    if isinstance(result, Exception):
        with pytest.raises(type(result), match=result.args[0]):
            Languages.identify_language(lang_code)
    else:
        assert Languages.identify_language(lang_code) == result
