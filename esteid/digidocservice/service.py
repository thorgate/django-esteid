# -*- coding: utf-8 -*-
import base64
import binascii
import logging
import os

from django.utils.encoding import force_text, force_bytes

from zeep import Client, Transport
from zeep.cache import SqliteCache
from zeep.exceptions import Fault
from zeep.helpers import serialize_object
from zeep.xsd import SkipValue

try:
    from zeep.settings import Settings as ZeepSettings

except ImportError:  # pragma: no cover
    # only occurs on zeep before 3.0
    ZeepSettings = None

from ..signature import verify_mid_signature

from .containers import BdocContainer
from .types import SignedDocInfo
from .util import get_bool, get_optional_bool


class DigiDocException(Exception):
    """ Unknown errors
    """

    def __init__(self, command, params, *args):
        self.command = command
        self.params = params

        super(DigiDocException, self).__init__(*args)


class DigiDocError(Exception):
    """ Known errors
    """

    def __init__(self, error_code, known_fault, *args):
        self.error_code = error_code
        self.known_fault = known_fault

        super(DigiDocError, self).__init__(*args)


class DigiDocNotOk(Exception):
    """ Used when an api is supposed to return status OK but does not
    """

    code = -1

    def __init__(self, response, message):
        self.response = response

        super(Exception, self).__init__(message)


class PreviouslyCreatedContainer(object):
    pass


class DataFile(object):
    def __init__(self, file_name, mimetype, content_type, size, content, info=None):
        self.file_name = file_name
        self.mimetype = mimetype
        self.content_type = content_type or DigiDocService.HASHCODE
        self.size = size
        self.content = content

        self.info = info


class DigiDocService(object):
    RESPONSE_STATUS_OK = "OK"

    # FIXME: error i18n (allow to set language in init, can be overwritten in mobile_authenticate/mobile_sign)
    ERROR_CODES = {
        -1: 'Päring ebaõnnestus, staatus: %s',
        100: 'Üldine viga.',
        101: 'Vigased sissetulevad parameetrid.',
        102: 'Mõned sissetulevad parameetrid on puudu.',
        103: 'Teenuse omanikul puudub õigus teha päringuid allkirja-kontrolli teenusesse (OCSP: AUTORISEERIMATA)',
        104: 'Teenusele juurdepääs pole lubatud.',
        105: 'Kasutajal puuduvad küsitud tüüpi sertifikaadid.',
        200: 'Üldine teenuse viga.',
        201: 'Kasutaja sertifikaat on puudu.',
        202: 'Sertifikaadi korrektsust polnud võimalik valideerida.',
        203: 'Sessioon on lukustatud teise SOAPi pärginu poolt.',
        300: 'Üldine viga seoses kasutaja telefoniga.',
        301: 'Pole Mobiil-ID kasutaja.',
        302: 'Sertifikaat ei kehti (OCSP: TAGASI VÕETUD).',
        303: 'Sertifikaat ei ole aktiveeritud ja/ või selle staatus on teadmata (OCSP: TEADMATA).',
        304: 'Sertifikaat on peatatud.',
        305: 'Sertifikaat on aegunud.',
        413: 'Sissetulev päring ületab teenuse lubatud mahupiiranguid.',
        503: 'Teenuse üheaegselt esitatud päringute piirang on ületatud.',
    }

    MID_STATUS_ERROR_CODES = {
        'EXPIRED_TRANSACTION': 'MobiilID allkirjastamise ajapiirang sai läbi.',
        'USER_CANCEL': 'Kasutaja katkestas allkirjastamise.',
        'NOT_VALID': 'Allkiri ei kehti.',
        'MID_NOT_READY': 'Mobiil-ID ei ole veel sellel telefonil aktiveeritud. Palun proovige hiljem uuesti.',
        'PHONE_ABSENT': 'Telefon ei ole kättesaadav.',
        'SENDING_ERROR': 'Ei suutnud telefonile Mobiil-ID päringut saata.',
        'SIM_ERROR': 'Telefoni SIM-kaardiga tekkis probleem.',
        'OCSP_UNAUTHORIZED': 'Mobiil-ID kasutajal ei ole lubatud teha OSCP päringuid.',
        'INTERNAL_ERROR': 'Serveri viga Mobiil-ID allkirjastamisel.',
        'REVOKED_CERTIFICATE': 'Allkirjastaja sertifikaat ei kehti.',
        'BAD_SIGNATURE': 'Signatuuri valideerimine ebaõnnestus.',
    }

    LANGUAGE_ET = 'EST'
    LANGUAGE_EN = 'ENG'
    LANGUAGE_RU = 'RUS'
    LANGUAGE_LT = 'LIT'

    HASHCODE = 'HASHCODE'
    EMBEDDED_BASE64 = 'EMBEDDED_BASE64'

    # Commands which don't need Sesscode as input
    SESSION_INIT_COMMANDS = [
        'StartSession',
        'MobileAuthenticate',
    ]

    def __init__(self, wsdl_url, service_name, mobile_message='Signing via python', transport=None):
        self.service_name = service_name
        self.mobile_message = mobile_message

        self.session_code = None
        self.data_files = []
        self.container = None

        if wsdl_url == 'https://tsp.demo.sk.ee/dds.wsdl':  # pragma: no branch
            assert service_name == 'Testimine', 'When using Test DigidocService the service name must be `Testimine`'

        the_transport = transport or Transport(cache=SqliteCache())

        if ZeepSettings is not None:  # pragma: no branch
            settings = ZeepSettings(strict=False)

            self.client = Client(wsdl_url, transport=the_transport, settings=settings)

        else:
            self.client = Client(wsdl_url, transport=the_transport, strict=False)

    def start_session(self, b_hold_session, sig_doc_xml=None, datafile=None):
        """Start a DigidocService session

        :return: True if session was started and session code was stored in I{session_code}
        """
        response = self.__invoke('StartSession', {
            'bHoldSession': b_hold_session,
            'SigDocXML': sig_doc_xml or SkipValue,
            'datafile': datafile or SkipValue,

            # This parameter is deprecated and exists only due to historical reasons. We need to specify it as
            #  SkipValue to keep zeep happy
            'SigningProfile': SkipValue,
        })

        if response['Sesscode']:
            self.data_files = []
            self.session_code = response['Sesscode']

            if sig_doc_xml:
                self.container = PreviouslyCreatedContainer()

            return True

        # If b_hold_session is set to False, response will not contain a session
        # in case of errors, exceptions are raised from __invoke anyway
        return False

    def mobile_authenticate(self, id_code, country, phone_nr, message=None, language=None,
                            return_cert_data=True, return_revocation_data=False):
        challenge = self.get_sp_challenge()

        response = self.__invoke('MobileAuthenticate', {
            # allow to not define IDCode - it's only required w/ Lithuanian Mobile-ID
            # see section 7.1 in http://www.sk.ee/upload/files/DigiDocService_spec_eng.pdf
            'IDCode': id_code or SkipValue,

            'CountryCode': country,

            'PhoneNo': phone_nr,
            'Language': self.parse_language(language),
            'ServiceName': self.service_name,
            'MessageToDisplay': message or self.mobile_message,
            'SPChallenge': force_text(binascii.hexlify(challenge)),

            'MessagingMode': 'asynchClientServer',
            'AsyncConfiguration': SkipValue,

            'ReturnCertData': get_optional_bool(return_cert_data),
            'ReturnRevocationData': get_optional_bool(return_revocation_data),
        }, no_raise=True)

        # Update session code
        if response['Sesscode']:  # pragma: no branch (only missing in older service versions)
            self.data_files = []
            self.session_code = response['Sesscode']

        if 'CertificateData' in response and response['CertificateData']:
            # certificate data is b64 encoded binary (not PEM)
            response['CertificateData'] = base64.b64decode(response['CertificateData'])

        else:
            response['CertificateData'] = None

        if 'RevocationData' in response and response['RevocationData']:
            # certificate data is b64 encoded binary (not PEM)
            response['RevocationData'] = base64.b64decode(response['RevocationData'])

        else:
            response['RevocationData'] = None

        return response, challenge

    def get_mobile_authenticate_status(self, wait=False):
        response = self.__invoke('GetMobileAuthenticateStatus', {
            'WaitSignature': get_bool(wait),
        }, no_raise=True)

        status_code, signature = response['Status'], None

        if 'Signature' in response and response['Signature']:
            signature = base64.b64decode(response['Signature'])

        return status_code, signature

    def create_signed_document(self, file_format='BDOC', signing_profile='LT_TM'):
        if self.container and isinstance(self.container, PreviouslyCreatedContainer):
            raise DigiDocException('CreateSignedDoc', {}, 'PreviouslyCreatedContainer already in session')

        versions = {
            'BDOC': '2.1',
        }
        containers = {
            'BDOC': BdocContainer,
        }

        if file_format not in versions:
            raise ValueError('File format should be one of: %s' % versions.keys())

        self.__invoke('CreateSignedDoc', {
            'Format': file_format,
            'Version': versions[file_format],

            # Either LT or LT_TM, see: http://sk-eid.github.io/dds-documentation/api/api_docs/#mobilesign
            'SigningProfile': signing_profile,
        })

        self.container = containers[file_format]

        return True

    def add_datafile(self, file_name, mimetype, content_type, size, content):
        if self.container and isinstance(self.container, PreviouslyCreatedContainer):
            raise DigiDocException('AddDataFile', {}, 'Cannot add files to PreviouslyCreatedContainer')

        assert self.container, 'Must create a signed document before adding files'
        assert content_type in [self.HASHCODE, self.EMBEDDED_BASE64], 'Invalid content_type'

        args = {
            'FileName': file_name,
            'MimeType': mimetype,
            'ContentType': content_type,
            'Content': SkipValue,
            'Size': size,

            'DigestType': SkipValue,
            'DigestValue': SkipValue,
        }

        # We only support HASHCODE format, see above
        if content_type == self.EMBEDDED_BASE64:
            args['Content'] = base64.b64encode(content)

        elif content_type == self.HASHCODE:
            args['DigestType'] = self.container.DEFAULT_HASH_ALGORITHM
            args['DigestValue'] = force_text(self.container.hash_code(content))

        response = self.__invoke('AddDataFile', args)

        # Get the file from the response info object
        info = next(iter([f for f in response['SignedDocInfo']['DataFileInfo'] if f['Filename'] == file_name]))

        self.data_files.append(DataFile(file_name, mimetype, content_type, size, content, info))

        return self.data_files

    def mobile_sign(self, id_code, country, phone_nr, language=None, signing_profile='LT_TM'):
        """ This can be used to add a signature to existing data files

            WARNING: Must have at least one datafile in the session
        """

        if not (self.container and isinstance(self.container, PreviouslyCreatedContainer)):
            assert self.data_files, 'To use MobileSign endpoint the application must ' \
                                    'add at least one data file to users session'

        response = self.__invoke('MobileSign', {
            'SignerIDCode': id_code,
            'SignersCountry': country,
            'SignerPhoneNo': phone_nr,
            'Language': self.parse_language(language),

            'Role': SkipValue,
            'City': SkipValue,
            'StateOrProvince': SkipValue,
            'PostalCode': SkipValue,
            'CountryName': SkipValue,

            'ServiceName': self.service_name,
            'AdditionalDataToBeDisplayed': self.mobile_message,

            # Either LT or LT_TM, see: http://sk-eid.github.io/dds-documentation/api/api_docs/#mobilesign
            'SigningProfile': signing_profile,

            'MessagingMode': 'asynchClientServer',
            'AsyncConfiguration': SkipValue,

            'ReturnDocInfo': SkipValue,
            'ReturnDocData': SkipValue,
        })

        return response

    def prepare_signature(self, certificate, token_id, role='', city='', state='', postal_code='', country='', signing_profile='LT_TM'):
        if not (self.container and isinstance(self.container, PreviouslyCreatedContainer)):
            assert self.data_files, 'To use PrepareSignature endpoint the application must ' \
                                    'add at least one data file to users session'

        response = self.__invoke('PrepareSignature', {
            'SignersCertificate': certificate,
            'SignersTokenId': token_id,
            'Role': role,
            'City': city,
            'State': state,
            'PostalCode': postal_code,
            'Country': country,
            # Either LT or LT_TM, see: http://sk-eid.github.io/dds-documentation/api/api_docs/#preparesignature
            'SigningProfile': signing_profile,
        })

        if response['Status'] == self.RESPONSE_STATUS_OK:
            return {
                'id': response['SignatureId'],
                'digest': response['SignedInfoDigest'],
            }

        raise DigiDocNotOk(response, self.ERROR_CODES[-1] % response['Status'])

    def finalize_signature(self, signature_id, signature_value):
        response = self._finalize_signature(signature_id, signature_value)

        if response['Status'] == self.RESPONSE_STATUS_OK:
            response_dict = serialize_object(response['SignedDocInfo'])

            return SignedDocInfo.from_dict(response_dict)

        raise DigiDocNotOk(response, self.ERROR_CODES[-1] % response['Status'])

    def close_session(self):
        response = self.__invoke('CloseSession')

        self.data_files = []
        self.session_code = None

        return response

    def get_signed_doc(self):
        response = self.__invoke('GetSignedDoc')

        if response['Status'] == self.RESPONSE_STATUS_OK:
            return base64.b64decode(force_bytes(response['SignedDocData']))

        raise DigiDocNotOk(response, self.ERROR_CODES[-1] % response['Status'])

    def get_signed_doc_info(self):
        response = self.__invoke('GetSignedDocInfo')
        response_dict = serialize_object(response['SignedDocInfo'])

        return SignedDocInfo.from_dict(response_dict)

    def get_status_info(self, wait=False):
        response = self.__invoke('GetStatusInfo', {
            'ReturnDocInfo': False,
            'WaitSignature': wait,
        })

        return response

    def __invoke(self, command, params=None, no_raise=False):
        params = params or {}

        if command not in self.SESSION_INIT_COMMANDS:
            params.update({'Sesscode': self.session_code})

        try:
            response = getattr(self.client.service, command)(**params)

            logging.debug('%s:Response: %s', command, response)

            if response == self.RESPONSE_STATUS_OK:
                return True

            elif response['Status'] == self.RESPONSE_STATUS_OK:
                return response

            elif no_raise:
                # Some service methods use the status field for other things (e.g. MobileAuthenticate)
                return response

            # This should usually not happen, hence the over-the-top raise Exception which gets re-raised as
            #  DigiDocException below
            raise Exception(response)

        except Fault as e:
            error_code = int(str(e))
            known_fault = self.ERROR_CODES.get(error_code, None)

            logging.debug('Response body [/%s - %s]: %s', command, error_code, e.message)

            if known_fault is not None:
                raise DigiDocError(error_code, known_fault,
                                   "Server result [/%s - %s]: %s" % (command, error_code, known_fault))

            else:
                logging.exception('Request to %s with params %s caused an error', command, params)
                raise DigiDocException(command, params, e)

        except Exception as e:
            logging.exception('Request to %s with params %s caused an error', command, params)

            raise DigiDocException(command, params, e)

    def get_file_data(self, the_files):
        # Add all files to memory
        for file in the_files:
            assert isinstance(file, DataFile)
            self.data_files.append(file)

        # Get bdoc container from DigidocService
        file_data = self.get_signed_doc()

        with self.to_bdoc(file_data) as container:
            file_data = container.data_files_format()

        return file_data

    def to_bdoc(self, file_data):
        return BdocContainer(file_data, self.data_files)

    def verify_mid_signature(self, certificate_data, sp_challenge, response_challenge, signature):
        return verify_mid_signature(certificate_data, sp_challenge, response_challenge, signature)

    def get_sp_challenge(self):
        return os.urandom(10)

    def parse_language(self, language):
        if language is None:
            return self.LANGUAGE_ET

        assert language in [self.LANGUAGE_ET, self.LANGUAGE_EN, self.LANGUAGE_RU, self.LANGUAGE_LT]

        return language

    def _finalize_signature(self, signature_id, signature_value):
        return self.__invoke('FinalizeSignature', {
            'SignatureId': signature_id,
            'SignatureValue': signature_value,
        })
