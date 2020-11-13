from datetime import datetime
from typing import List, TYPE_CHECKING, Union

import attr
import pytz
from oscrypto.asymmetric import load_certificate


if TYPE_CHECKING:
    from oscrypto.asymmetric import Certificate as OsCryptoCertificate
    from asn1crypto.cms import Certificate as Asn1CryptoCertificate

import pyasice

from esteid.util import (
    camel_2_py,
    convert_status,
    convert_time,
    get_instance_converter,
    get_name_from_legacy_common_name,
    get_typed_list_converter,
    get_typed_list_validator,
)


class FromDictMixin(object):
    @classmethod
    def from_dict(cls, the_dict):
        return cls(**camel_2_py(the_dict))


@attr.s
class CertificatePolicy(FromDictMixin):
    oid = attr.ib()
    url = attr.ib(default=None)
    description = attr.ib(default=None)


@attr.s
class Certificate(FromDictMixin):
    issuer = attr.ib()
    issuer_serial = attr.ib()
    subject = attr.ib()
    valid_from: datetime = attr.ib(converter=convert_time)
    valid_to: datetime = attr.ib(converter=convert_time)

    policies = attr.ib(
        default=attr.Factory(list),
        validator=[
            attr.validators.instance_of(list),
            get_typed_list_validator(CertificatePolicy),
        ],
        converter=get_typed_list_converter(CertificatePolicy),
    )

    @classmethod
    def from_certificate(cls, cert: "Union[bytes, Asn1CryptoCertificate, OsCryptoCertificate]"):
        if isinstance(cert, bytes):
            cert = load_certificate(cert)
        cert_asn1: "Asn1CryptoCertificate" = getattr(cert, "asn1", cert)
        personal = cert_asn1.subject.native
        issuer = cert_asn1["tbs_certificate"]["issuer"]
        serial = cert_asn1["tbs_certificate"]["serial_number"].native

        validity = cert_asn1["tbs_certificate"]["validity"].native
        valid_from: datetime = validity["not_before"]
        valid_to: datetime = validity["not_after"]

        return cls(
            issuer=issuer.human_friendly,
            issuer_serial=str(serial),
            subject=personal["common_name"],
            valid_from=valid_from.replace(microsecond=0).astimezone(pytz.utc),
            valid_to=valid_to.replace(microsecond=0).astimezone(pytz.utc),
        )


@attr.s
class ResponderCertificate(Certificate):
    pass


@attr.s
class Signer(FromDictMixin):
    id_code = attr.ib()

    # Note: This should also support common_name argument coming in
    full_name = attr.ib()

    certificate: Certificate = attr.ib(
        validator=attr.validators.instance_of(Certificate), converter=get_instance_converter(Certificate)
    )

    @staticmethod
    def prepare_kwargs(kwargs):
        kwargs = camel_2_py(kwargs)
        full_name = kwargs.get("full_name", None)

        # If the full_name is None, check common_name field and use that
        if full_name is None:
            full_name = get_name_from_legacy_common_name(kwargs.pop("common_name", None))

        kwargs["full_name"] = full_name

        return kwargs

    @classmethod
    def from_certificate(cls, cert: "Union[bytes, Asn1CryptoCertificate, OsCryptoCertificate]"):
        """
        Get personal info from an oscrypto/asn1crypto Certificate object

        For a closer look at where the attributes come from:
        asn1crypto.x509.NameType
        """
        if isinstance(cert, bytes):
            cert = load_certificate(cert)
        cert: "Asn1CryptoCertificate" = getattr(cert, "asn1", cert)
        subject = cert.subject.native

        # ID codes usually given as PNO{EE,LT,LV}-XXXXXX.
        # LV ID codes contain a dash so we need to be careful about it.
        id_code = subject["serial_number"]
        if id_code.startswith("PNO"):
            prefix, id_code = id_code.split("-", 1)

        given_name = subject["given_name"]
        surname = subject["surname"]
        return cls(
            certificate=Certificate.from_certificate(cert),
            full_name=f"{given_name} {surname}",
            id_code=id_code,
        )


@attr.s
class Confirmation(FromDictMixin):
    produced_at = attr.ib()  # this might be a timestamp
    responder_id = attr.ib()

    responder_certificate = attr.ib(
        validator=attr.validators.instance_of(ResponderCertificate),
        converter=get_instance_converter(ResponderCertificate),
    )


@attr.s
class SignatureProductionPlace(FromDictMixin):
    postal_code = attr.ib()
    country_name = attr.ib()
    city = attr.ib()
    state_or_province = attr.ib()


@attr.s
class SignerRole(FromDictMixin):
    role = attr.ib()
    certified = attr.ib()


@attr.s
class SignatureInfo(FromDictMixin):
    signing_time = attr.ib(validator=attr.validators.instance_of(datetime), converter=convert_time)
    status = attr.ib(converter=convert_status)
    id = attr.ib()

    signer: Signer = attr.ib(
        validator=attr.validators.instance_of(Signer),
        converter=get_instance_converter(Signer, prepare_kwargs=Signer.prepare_kwargs),
    )
    confirmation: Confirmation = attr.ib(
        validator=attr.validators.instance_of(Confirmation), converter=get_instance_converter(Confirmation)
    )

    signature_production_place = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(SignatureProductionPlace)),
        converter=attr.converters.optional(get_instance_converter(SignatureProductionPlace)),
        default=None,
    )

    signer_role = attr.ib(
        default=attr.Factory(list),
        validator=[
            attr.validators.instance_of(list),
            get_typed_list_validator(SignerRole),
        ],
        converter=get_typed_list_converter(SignerRole),
    )

    error = attr.ib(default=None)
    crl_info = attr.ib(default=None)

    # references Timestamps object in the docs, currently we do not parse it to a internal structure
    # http://sk-eid.github.io/dds-documentation/api/api_docs/#signeddocinfo
    timestamps = attr.ib(default=None)


@attr.s
class DataFileInfo(FromDictMixin):
    size = attr.ib()
    id = attr.ib()
    mime_type = attr.ib()
    content_type = attr.ib()
    digest_value = attr.ib()
    digest_type = attr.ib()
    filename = attr.ib()

    # Note: This is not documented as of 19:35 20.11.2017
    attributes = attr.ib(default=None)


@attr.s
class SignedDocInfo(FromDictMixin):
    format = attr.ib(default="BDOC")
    version = attr.ib(default="2.1")
    mime_type = attr.ib(default=pyasice.Container.MIME_TYPE)

    data_file_info: List[DataFileInfo] = attr.ib(
        default=attr.Factory(list),
        validator=[
            attr.validators.instance_of(list),
            get_typed_list_validator(DataFileInfo),
        ],
        converter=get_typed_list_converter(DataFileInfo),
    )

    signature_info: List[SignatureInfo] = attr.ib(
        default=attr.Factory(list),
        validator=[
            attr.validators.instance_of(list),
            get_typed_list_validator(SignatureInfo),
        ],
        converter=get_typed_list_converter(SignatureInfo),
    )


class DataFile:
    def __init__(self, file_name, mimetype, content_type, size, content, info=None):
        self.file_name = file_name
        self.mimetype = mimetype
        self.content_type = content_type
        self.size = size
        self.content = content

        self.info = info
