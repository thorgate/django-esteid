"""
Translations smoke test
"""
import re
from pathlib import Path

import pytest

from django.utils.translation import gettext, override

import esteid
from esteid.constants import Languages


@pytest.mark.parametrize("lang", Languages._MAP_ISO_639_1_TO_MID.keys())
def test_translations(lang):
    pofile = Path(esteid.__file__).parent / "locale" / lang / "LC_MESSAGES" / "django.po"
    match = None
    with open(pofile) as f:
        while not match:
            line = next(f)
            match = re.match(r'^msgid "(.+)"$', line.rstrip())
        translatable = match.group(1)
        line = next(f)
        translated = re.match(r'^msgstr "(.*)"$', line.rstrip()).group(1)

    with override(lang):
        # NOTE:
        #  if this fails but translations seem to be valid,
        #  it may happen due to multiline msgstr's in the PO file.
        #  In this case the `translated` regexp would need to match over multiple lines.
        assert gettext(translatable) == translated if translated else translatable
