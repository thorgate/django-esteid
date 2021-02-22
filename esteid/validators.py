import re

from esteid.constants import Countries
from esteid.exceptions import InvalidIdCode, InvalidParameter


ID_CODE_EE_REGEXP = re.compile(r"^[1-6] \d{2} [01]\d [0123]\d \d{4}$", re.VERBOSE)
ID_CODE_LT_REGEXP = ID_CODE_EE_REGEXP
ID_CODE_LV_REGEXP = re.compile(r"^\d{6}-\d{5}$")


def id_code_ee_is_valid(id_code: str) -> bool:
    """
    Validates Estonian ID code, including checksum.

    https://et.wikipedia.org/wiki/Isikukood
    """
    if isinstance(id_code, str) and bool(re.match(ID_CODE_EE_REGEXP, id_code)):
        step1_factors = "1234567891"
        checksum = sum([int(i) * int(d) for i, d in zip(step1_factors, id_code[:10])]) % 11
        if checksum == 10:
            step2_factors = "3456789123"
            checksum = sum([int(i) * int(d) for i, d in zip(step2_factors, id_code[:10])]) % 11
            if checksum == 10:
                checksum = 0
        if int(id_code[-1]) == checksum:
            return True
    return False


def id_code_lv_is_valid(id_code: str) -> bool:
    """
    Validates Latvian ID code

    Given the input in the following format ABCDEF-XGHIZ,
    Z must equal to (1101-(1*A+6*B+3*C+7*D+9*E+10*F+5*X+8*G+4*H+2*I)) | Mod 11 | Mod 10.
    """
    if isinstance(id_code, str) and bool(re.match(ID_CODE_LV_REGEXP, id_code)):
        id_code = id_code.replace("-", "")
        factors = [1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        checksum = (1101 - sum([i * int(d) for i, d in zip(factors, id_code[:10])])) % 11 % 10
        if int(id_code[-1]) == checksum:
            return True
    return False


# Lithuanian ID code format is the same as Estonian.
id_code_lt_is_valid = id_code_ee_is_valid


ID_CODE_VALIDATORS = {
    Countries.ESTONIA: id_code_ee_is_valid,
    Countries.LATVIA: id_code_lv_is_valid,
    Countries.LITHUANIA: id_code_lt_is_valid,
}


def validate_id_code(id_code, country):
    try:
        validator = ID_CODE_VALIDATORS[country]
    except (KeyError, TypeError) as e:
        raise InvalidParameter(f"Unsupported country '{country}'", param="country") from e

    if not validator(id_code):
        # Find country name from Countries attributes
        cty = next(name for name, value in iter(Countries.__dict__.items()) if value == country)
        raise InvalidIdCode(f"ID code '{id_code}' is not valid for {cty.capitalize()}")
