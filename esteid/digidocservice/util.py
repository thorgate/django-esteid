from collections import OrderedDict
from datetime import datetime
import re

from django.utils import timezone
from zeep.helpers import serialize_object

from zeep.xsd import SkipValue, CompoundValue


def get_bool(value):
    return 'TRUE' if value else 'FALSE'


def get_optional_bool(value):
    return 'TRUE' if value else SkipValue


def convert_status(status):
    if isinstance(status, bool):
        return status

    return status.lower() == 'ok'


def camel_2_py(the_dict):
    new_dict = {}
    for key, val in the_dict.items():

        if len(re.sub(r"([A-Z])", r" \1", key).split()) == len(key):
            parts = [key.lower()]

        else:
            key = key.replace('ID', 'Id').replace('CRL', 'Crl')
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
        if isinstance(value, CompoundValue):
            value = serialize_object(value)

        if isinstance(value, (dict, OrderedDict)):
            return cls(**prepare_kwargs(value))

        return value

    return _convert_instance


def get_typed_list_validator(klass):
    def _get_typed_list_validator(inst, attr, value):
        if not isinstance(value, list):
            raise TypeError('Value MUST be a list')

        if not all(isinstance(x, klass) for x in value):
            raise TypeError('Value MUST be a list of {}'.format(klass))

    return _get_typed_list_validator


def get_typed_list_converter(klass):
    converter = get_instance_converter(klass)

    def _get_typed_list_converter(value):
        return [converter(x) for x in value]

    return _get_typed_list_converter
