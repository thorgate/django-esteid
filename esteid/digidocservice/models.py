from datetime import datetime
import re

from django.utils import timezone
from suds.sudsobject import asdict, Object as SudsObject


class BaseDigidocServiceObject(object):
    def __str__(self):
        return '%s: %s' % (self.__class__.__name__, self.as_dict())

    def as_dict(self):
        return self.make_dict(self)

    @staticmethod
    def make_dict(instance):
        if not isinstance(instance, BaseDigidocServiceObject):
            raise Exception('BaseDigidocServiceObject.make_dict instance should be an instance of BaseDigidocServiceObject')

        result = {}

        for key, val in instance.__dict__.items():
            if key[:2] == '__':
                continue

            if isinstance(val, (list, tuple)):
                val = [BaseDigidocServiceObject.make_dict(x) for x in val]

            elif isinstance(val, BaseDigidocServiceObject):
                val = BaseDigidocServiceObject.make_dict(val)

            result[key] = val

        return result

    @classmethod
    def from_dict(cls, the_data):
        if isinstance(the_data, SudsObject):
            the_data = asdict(the_data)

        kwargs = BaseDigidocServiceObject.camel_2_py(the_data)

        return cls(**kwargs)

    @classmethod
    def camel_2_py(cls, the_dict):
        new_dict = {}
        for key, val in the_dict.items():

            if len(re.sub(r"([A-Z])", r" \1", key).split()) == len(key):
                parts = [key.lower()]

            else:
                key = key.replace('ID', 'Id')
                parts = re.sub(r"([A-Z])", r" \1", key).split()

            new_dict["_".join([x.lower() for x in parts])] = val

        return new_dict

    @classmethod
    def ensure_instance(cls, model, the_data, allow_list=False, allow_none=False):
        if the_data is None and allow_none:
            return None

        if not isinstance(the_data, model):
            if isinstance(the_data, SudsObject):
                the_data = asdict(the_data)

            if isinstance(the_data, (list, tuple)):
                if not allow_list:
                    raise Exception('BaseDigidocServiceObject.ensure_instance: Lists not allowed in this context')

                result = []

                for item in the_data:
                    result.append(model.from_dict(item))

                return result

            elif isinstance(the_data, dict):
                return model.from_dict(the_data)

            else:
                raise Exception('BaseDigidocServiceObject.ensure_instance: The data must be one of: [cls, list, tuple, dict]')

        else:
            # It's an instance of the required class, all good
            return the_data

    @classmethod
    def convert_time(cls, timestamp):
        if isinstance(timestamp, datetime):
            if timezone.is_naive(timestamp):
                timestamp = timezone.make_aware(timestamp, timezone.utc)

            return timestamp

        return timezone.make_aware(datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ"), timezone.utc)

    @classmethod
    def convert_status(cls, status):
        if isinstance(status, bool):
            return status

        return status.lower() == 'ok'


class DataFileInfo(BaseDigidocServiceObject):
    def __init__(self, size, id, mime_type, content_type, digest_value, digest_type, filename):
        self.size = size
        self.id = id
        self.mime_type = mime_type
        self.content_type = content_type
        self.digest_value = digest_value
        self.digest_type = digest_type
        self.filename = filename


class CertificatePolicy(BaseDigidocServiceObject):
    def __init__(self, url, oid, description=None):
        self.description = description
        self.url = url
        self.oid = oid


class Certificate(BaseDigidocServiceObject):
    def __init__(self, valid_from, issuer_serial, issuer, valid_to, subject, policies):
        self.valid_from = valid_from
        self.issuer_serial = issuer_serial
        self.issuer = issuer
        self.valid_to = valid_to
        self.subject = subject

        self.policies = BaseDigidocServiceObject.ensure_instance(CertificatePolicy, policies, allow_list=True)


class Signer(BaseDigidocServiceObject):
    def __init__(self, id_code, certificate, common_name=None, full_name=None):
        assert common_name or full_name

        self.id_code = id_code
        self.full_name = full_name or self.parse_common_name(common_name, id_code)

        self.certificate = BaseDigidocServiceObject.ensure_instance(Certificate, certificate)

    @staticmethod
    def parse_common_name(common_name, id_code):
        common_name = common_name.replace(str(id_code), '')

        if common_name[-1] == ',':
            common_name = common_name[:-1]

        parts = common_name.split(',')
        parts.reverse()

        return ' '.join([Signer.fix_name_part(x) for x in parts])

    @staticmethod
    def fix_name_part(part):
        uc_first = lambda x: '%s%s' % (x[0].upper(), x[1:].lower())

        if len(re.findall(r"\W", part, flags=re.UNICODE)) == 0:
            return uc_first(part)

        return re.sub(r"([\w]+)", lambda m: uc_first(m.group(1)), part, flags=re.UNICODE)


class ResponderCertificate(Certificate):
    pass


class Confirmation(BaseDigidocServiceObject):
    def __init__(self, produced_at, responder_id, responder_certificate):
        self.produced_at = produced_at
        self.responder_id = responder_id

        self.responder_certificate = BaseDigidocServiceObject.ensure_instance(ResponderCertificate, responder_certificate)


class SignatureProductionPlace(BaseDigidocServiceObject):
    def __init__(self, postal_code, country_name, city, state_or_province):
        self.postal_code = postal_code
        self.country_name = country_name
        self.city = city
        self.state_or_province = state_or_province


class SignerRole(BaseDigidocServiceObject):
    def __init__(self, role, certified):
        self.role = role
        self.certified = certified


class SignatureInfo(BaseDigidocServiceObject):
    def __init__(self, signing_time, status, id, signer, confirmation, signature_production_place=None, signer_role=None):
        self.signing_time = self.convert_time(signing_time)
        self.status = self.convert_status(status)
        self.id = id

        self.signer = BaseDigidocServiceObject.ensure_instance(Signer, signer)
        self.confirmation = BaseDigidocServiceObject.ensure_instance(Confirmation, confirmation)

        self.signature_production_place = BaseDigidocServiceObject.ensure_instance(SignatureProductionPlace, signature_production_place,
                                                                                   allow_none=True)

        self.signer_role = BaseDigidocServiceObject.ensure_instance(SignerRole, signer_role, allow_list=True, allow_none=True)


class SignedDocInfo(BaseDigidocServiceObject):
    def __init__(self, format, version, data_file_info, signature_info):
        self.format = format
        self.version = version

        self.data_file_info = BaseDigidocServiceObject.ensure_instance(DataFileInfo, data_file_info, allow_list=True)
        self.signature_info = BaseDigidocServiceObject.ensure_instance(SignatureInfo, signature_info, allow_list=True)
