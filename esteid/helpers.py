import re


def ucs_to_utf8(val):
    return bytes([ord(x) for x in re.sub(r"\\([0-9ABCDEF]{1,2})",
                                         lambda x: chr(int(x.group(1), 16)), val)]).decode('utf-8')


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
    l = None

    for part in dn.strip().split(','):
        if '=' in part:
            part = part.split('=')

            l = part[0]
            res[l] = part[1]

        elif l:
            res[l] = '{0},{1}'.format(res[l], part)

    return res
