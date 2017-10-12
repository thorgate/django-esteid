from zeep.xsd import SkipValue


def get_bool(value):
    return 'TRUE' if value else 'FALSE'


def get_optional_bool(value):
    return 'TRUE' if value else SkipValue
