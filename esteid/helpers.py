import re
import sys

from six import unichr


def ucs_to_utf8(val):
    klass = bytes

    # For py2:
    #  - bytes is an alias for str: use bytearray instead
    if sys.version_info[0] < 3:
        klass = bytearray

    return klass([ord(x) for x in re.sub(r"\\([0-9ABCDEF]{1,2})",
                                         lambda x: unichr(int(x.group(1), 16)), val)]).decode('utf-8')


def get_name_from_legacy_common_name(common_name):
    common_name = common_name.replace('\\,', ',')
    common_name = common_name.strip().rstrip(',')

    parts = common_name.split(',')[:-1]
    parts.reverse()

    return ' '.join(parts).title()


def get_id_from_legacy_common_name(common_name):
    common_name = common_name.strip().rstrip(',')

    return common_name.split(',')[-1]


def parse_legacy_dn(dn):
    x_client = dn.strip().strip('/').split('/')

    res = {}

    for part in x_client:
        part = ucs_to_utf8(part).split('=')
        res[part[0]] = part[1]

    return res


def parse_rfc_dn(dn):
    dn = ucs_to_utf8(dn).replace('\,', ',')
    res = {}
    c_key = None

    for part in dn.strip().split(','):
        if '=' in part:
            part = part.split('=')

            c_key = part[0]
            res[c_key] = part[1]

        elif c_key:
            res[c_key] = u'{0},{1}'.format(res[c_key], part)

    return res
