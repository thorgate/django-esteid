import hashlib
import os
import re
from collections import OrderedDict
from datetime import datetime

import requests
from django.utils import timezone
from django.utils.module_loading import import_string

from esteid.constants import HASH_ALGORITHMS
from esteid.settings import ESTEID_GET_REQUEST_SESSION


def secure_random(n):
    return os.urandom(n)


def generate_hash(algorithm, data):
    """Hash the data with the supplied algorithm

    https://github.com/SK-EID/smart-id-documentation#33-hash-algorithms
    https://github.com/SK-EID/MID#231-supported-hashing-algorithms
    """
    if algorithm.upper() not in HASH_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm {algorithm}")

    hash_method = getattr(hashlib, algorithm.lower())
    digest = hash_method(data).digest()

    return digest


def convert_status(status):
    if isinstance(status, bool):
        return status

    return status.lower() == "ok"


def camel_2_py(the_dict):
    new_dict = {}
    for key, val in the_dict.items():
        if len(re.sub(r"([A-Z])", r" \1", key).split()) == len(key):
            parts = [key.lower()]

        else:
            key = key.replace("ID", "Id").replace("CRL", "Crl")
            parts = re.sub(r"([A-Z])", r" \1", key).split()

        new_dict["_".join([x.lower() for x in parts])] = val

    return new_dict


def convert_time(timestamp):
    if not timestamp:
        return None

    if isinstance(timestamp, datetime):
        if timezone.is_naive(timestamp):
            timestamp = timezone.make_aware(timestamp, timezone.utc)

        return timestamp

    return timezone.make_aware(datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ"), timezone.utc)


def get_instance_converter(cls, prepare_kwargs=camel_2_py):
    def _convert_instance(value):
        if isinstance(value, (dict, OrderedDict)):
            return cls(**prepare_kwargs(value))

        return value

    return _convert_instance


def get_typed_list_validator(klass):
    def _get_typed_list_validator(inst, attr, value):
        if not isinstance(value, list):
            raise TypeError("Value MUST be a list")

        if not all(isinstance(x, klass) for x in value):
            raise TypeError(f"Value MUST be a list of {klass}")

    return _get_typed_list_validator


def get_typed_list_converter(klass):
    converter = get_instance_converter(klass)

    def _get_typed_list_converter(value):
        return [converter(x) for x in value]

    return _get_typed_list_converter


def get_name_from_legacy_common_name(common_name):
    common_name = common_name.replace("\\,", ",")
    common_name = common_name.strip().rstrip(",")

    parts = common_name.split(",")[:-1]
    parts.reverse()

    return " ".join(parts).title()


def get_id_from_legacy_common_name(common_name):
    common_name = common_name.strip().rstrip(",")

    return common_name.split(",")[-1]


def ucs_to_utf8(val):
    return bytes([ord(x) for x in re.sub(r"\\([0-9ABCDEF]{1,2})", lambda x: chr(int(x.group(1), 16)), val)]).decode(
        "utf-8"
    )


def parse_legacy_dn(dn):
    x_client = dn.strip().strip("/").split("/")

    res = {}

    for part in x_client:
        part = ucs_to_utf8(part).split("=")
        res[part[0]] = part[1]

    return res


def parse_rfc_dn(dn):
    dn = ucs_to_utf8(dn).replace("\\,", ",")
    res = {}
    c_key = None

    for part in dn.strip().split(","):
        if "=" in part:
            part = part.split("=")

            c_key = part[0]
            res[c_key] = part[1]

        elif c_key:
            res[c_key] = f"{res[c_key]},{part}"

    return res


def default_get_request_session():
    return requests.Session()


def get_request_session_method():
    return import_string(ESTEID_GET_REQUEST_SESSION)


def get_request_session_instance():
    return get_request_session_method()()
