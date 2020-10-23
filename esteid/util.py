import hashlib
import os
import re
from collections import OrderedDict
from datetime import datetime

from django.utils import timezone

from esteid.constants import HASH_ALGORITHMS


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
            raise TypeError("Value MUST be a list of {}".format(klass))

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
