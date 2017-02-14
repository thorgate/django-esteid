# -*- coding: utf-8 -*-
# Needs suds_jurko
import base64
import binascii
import logging
import os

from django.utils.encoding import force_text, force_bytes
from suds import WebFault
from suds.client import Client
from suds.plugin import MessagePlugin

from .containers import BdocContainer


class DigiDocException(Exception):
    """ Unknown errors
    """

    def __init__(self, command, params, *args, **kwargs):
        self.command = command
        self.params = params

        super().__init__(*args, **kwargs)


class DigiDocError(Exception):
    """ Known errors
    """

    def __init__(self, error_code, *args, **kwargs):
        self.error_code = error_code

        super().__init__(*args, **kwargs)


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


class SoapFixer(MessagePlugin):
    def marshalled(self, context):
        context.envelope.nsprefixes = {
            'ns1': "http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl",
            'SOAP-ENV': "http://schemas.xmlsoap.org/soap/envelope/",
        }

        if context.envelope.attributes:
            context.envelope.attributes = list(filter(lambda attr: attr.prefix != 'SOAP-ENV' and attr.name != 'encodingStyle',
                                                      context.envelope.attributes))

        context.envelope.walk(self.fix_namespaces)

    def fix_namespaces(self, element):
        if element.prefix:
            if element.prefix != 'ns1' and element.prefix[:2] == 'ns':
                element.prefix = 'ns1'

        if element.name == 'Header':
            del element

        elif element.name == 'Body':
            element.prefix = 'SOAP-ENV'

        elif element.attributes:
            element.attributes = list(filter(lambda attr: attr.prefix != 'xsi' and attr.name != 'type', element.attributes))


class DigiDocService(object):
    HOST_TEST = 'TEST'
    HOST_LIVE = 'LIVE'

    WSDL_HOSTS = {
        HOST_TEST: "https://tsp.demo.sk.ee/?wsdl",
        HOST_LIVE: "https://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl",
    }

    RESPONSE_STATUS_OK = "OK"

    ERROR_CODES = {
        100: 'Üldine viga.',
        101: 'Vigased sissetulevad parameetrid.',
        102: 'Mõned sissetulevad parameetrid on puudu.',
        103: 'Teenuse omanikul puudub õigus teha päringuid allkirja-kontrolli teenusesse (OCSP: AUTORISEERIMATA)',
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
        'REVOKED_CERTIFICATE': 'Allkirjastaja sertifikaat ei kehti.'
    }

    LANGUAGE_ET = 'EST'
    LANGUAGE_EN = 'ENG'
    LANGUAGE_RU = 'RUS'
    LANGUAGE_LT = 'LIT'

    HASHCODE = 'HASHCODE'
    EMBEDDED_BASE64 = 'EMBEDDED_BASE64'

    def __init__(self, service_name, mobile_message='Signing via python', client_type=None, debug=False):
        self.service_name = service_name
        self.mobile_message = mobile_message

        self.session_code = None
        self.data_files = []
        self.container = None

        if client_type is None:
            client_type = self.HOST_TEST

        assert client_type in [self.HOST_TEST, self.HOST_LIVE]

        if client_type == self.HOST_TEST:
            assert service_name == 'Testimine'

        plugin = SoapFixer()
        self.client = Client(self.WSDL_HOSTS[client_type], xstq=False, prefixes=True, prettyxml=True, plugins=[plugin])

        self.debug = debug

    def start_session(self, b_hold_session, signing_profile=None, sig_doc_xml=None, datafile=None):
        response = self.__invoke('StartSession', {
            'bHoldSession': b_hold_session,
            'SigningProfile': signing_profile,
            'SigDocXML': sig_doc_xml,
            'datafile': datafile,
        })

        if response['Sesscode']:
            self.data_files = []
            self.session_code = response['Sesscode']

            if sig_doc_xml:
                self.container = PreviouslyCreatedContainer()

            return True

        return False

    def mobile_authenticate(self, phone_nr, message=None, language=None):
        if language is None:
            language = self.LANGUAGE_ET

        assert language in [self.LANGUAGE_ET, self.LANGUAGE_EN, self.LANGUAGE_RU, self.LANGUAGE_LT]

        response = self.__invoke('MobileAuthenticate', {
            'PhoneNo': phone_nr,
            'Language': language,
            'ServiceName': self.service_name,
            'MessageToDisplay': message or self.mobile_message,
            'SPChallenge': force_text(binascii.hexlify(os.urandom(10))),
            'MessagingMode': 'asynchClientServer',
        })

        return response

    def get_mobile_authenticate_status(self, wait=False):
        response = self.__invoke('GetMobileAuthenticateStatus', {
            'WaitSignature': 'TRUE' if wait else 'FALSE',
        }, no_raise=True)

        return response

    def create_signed_document(self, file_format='BDOC'):
        if self.container and isinstance(self.container, PreviouslyCreatedContainer):
            raise DigiDocException('CreateSignedDoc', {}, 'PreviouslyCreatedContainer already in session')

        versions = {
            # 'DIGIDOC-XML': '1.3',
            'BDOC': '2.1',
        }
        containers = {
            'BDOC': BdocContainer,
        }

        assert file_format in versions, 'File format should be one of: %s' % versions.keys()

        self.__invoke('CreateSignedDoc', {
            'Format': file_format,
            'Version': versions[file_format],
        })

        self.container = containers[file_format]

        return True

    def add_datafile(self, file_name, mimetype, content_type, size, content):
        if self.container and isinstance(self.container, PreviouslyCreatedContainer):
            raise DigiDocException('AddDataFile', {}, 'Cannot add files to PreviouslyCreatedContainer')

        assert self.container, 'Must create a signed document before adding files'
        assert content_type in [self.HASHCODE, self.EMBEDDED_BASE64]
        assert content_type == self.HASHCODE, 'Currently only HASHCODE mode works'

        digest_type = self.container.DEFAULT_HASH_ALGORITHM
        digest_value = force_text(self.container.hash_code(content))

        args = {
            'FileName': file_name,
            'MimeType': mimetype,
            'ContentType': content_type,
            'Size': size,

            'DigestType': digest_type,
            'DigestValue': digest_value,
        }

        if content_type == self.EMBEDDED_BASE64:
            args['Content'] = base64.b64encode(content)

        response = self.__invoke('AddDataFile', args)

        info = None
        for file in response['SignedDocInfo']['DataFileInfo']:
            if file['Filename'] == file_name:
                info = file
                break

        self.data_files.append(DataFile(file_name, mimetype, content_type, size, content, info))

        return self.data_files

    def mobile_sign(self, id_code, phone_nr, language=None):
        """ This can be used to add a signature to existing data files

            WARNING: Must have at least one datafile in the session
        """

        if not (self.container and isinstance(self.container, PreviouslyCreatedContainer)):
            assert self.data_files, 'To use MobileSign endpoint the application must add at least one data file to users session'

        if language is None:
            language = self.LANGUAGE_ET

        assert language in [self.LANGUAGE_ET, self.LANGUAGE_EN, self.LANGUAGE_RU, self.LANGUAGE_LT]

        response = self.__invoke('MobileSign', {
            'SignerIDCode': id_code,
            'SignerPhoneNo': phone_nr,
            'Language': language,

            'ServiceName': self.service_name,
            'AdditionalDataToBeDisplayed': self.mobile_message,

            'MessagingMode': 'asynchClientServer',
            'ReturnDocInfo': '',
            'ReturnDocData': '',
        })

        return response

    def prepare_signature(self, certificate, token_id, role='', city='', state='', postal_code='', country=''):
        if not (self.container and isinstance(self.container, PreviouslyCreatedContainer)):
            assert self.data_files, 'To use PrepareSignature endpoint the application must add at least one data file to users session'

        response = self.__invoke('PrepareSignature', {
            'SignersCertificate': certificate,
            'SignersTokenId': token_id,
            'Role': role,
            'City': city,
            'State': state,
            'PostalCode': postal_code,
            'Country': country,
        })

        if response['Status'] == self.RESPONSE_STATUS_OK:
            return {
                'id': response['SignatureId'],
                'digest': response['SignedInfoDigest'],
            }

        return None

    def finalize_signature(self, signature_id, signature_value):
        response = self.__invoke('FinalizeSignature', {
            'SignatureId': signature_id,
            'SignatureValue': signature_value,
        })

        return response['Status'] == self.RESPONSE_STATUS_OK

    def close_session(self):
        response = self.__invoke('CloseSession')

        self.data_files = []
        self.session_code = None

        return response

    def get_signed_doc(self):
        response = self.__invoke('GetSignedDoc')

        if response['Status'] == self.RESPONSE_STATUS_OK:
            return base64.b64decode(force_bytes(response['SignedDocData']))

        else:
            return None

    def get_signed_doc_info(self):
        response = self.__invoke('GetSignedDocInfo')

        return response

    def get_status_info(self, wait=False):
        response = self.__invoke('GetStatusInfo', {
            'ReturnDocInfo': False,
            'WaitSignature': wait,
        })

        return response

    def __invoke(self, command, params=None, no_raise=False):
        params = params or {}

        if command != 'StartSession':
            params.update({'Sesscode': self.session_code})

        try:
            response = getattr(self.client.service, command)(**params)
            if self.debug:
                logging.info('%s:Response: %s', command, response)

            if response == self.RESPONSE_STATUS_OK:
                return True

            elif response['Status'] == self.RESPONSE_STATUS_OK:
                return response

            if no_raise:
                return response

            raise Exception(response)

        except WebFault as e:
            error_code = e.fault.faultstring
            known_fault = self.ERROR_CODES.get(int(error_code), None)

            if self.debug:
                logging.info('Response body [/%s - %s]: %s', command, error_code, e.document.str())

            if known_fault is not None:
                raise DigiDocError(error_code, "Server result [/%s - %s]: %s" % (command, error_code, known_fault))

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
