import os
from tempfile import NamedTemporaryFile

import binascii
import logging
import typing

from .bdoc2.container import BDoc2File
from .bdoc2.exceptions import BDoc2Error
from .bdoc2.signature_verifier import verify_cryptography
from .bdoc2.utils import prepare_signature, finalize_signature
from .bdoc2.xmlsig import XmlSignature
from .digidocservice.service import DigiDocError
from .session import open_container, get_esteid_session, update_esteid_session, delete_esteid_session

if typing.TYPE_CHECKING:
    from .generic import GenericDigitalSignViewMixin


logger = logging.getLogger(__name__)


class BaseAction(object):
    @classmethod
    def do_action(cls, view: "GenericDigitalSignViewMixin", params):
        raise NotImplementedError


class NoAction(object):
    @classmethod
    def do_action(cls, view, params):
        return {'success': True}


class IdCardPrepareAction(BaseAction):
    @classmethod
    def do_action(cls, view: "GenericDigitalSignViewMixin", params: dict = None, *, certificate: str = None,
                  container_path: str = None):
        """
        The old API is to pass a dict of params (previously confusingly named `action_kwargs`),
        the keyword args are added here for clarity as to what the method accepts

        :param view:
        :param params:
        :param certificate: HEX-encoded certificate from the ID card
        :return:
        """
        request = view.request

        if not certificate:
            certificate = params['certificate']

        if container_path is None:
            container_path = params.get("container_path", "")

        delete_esteid_session(request)

        if not certificate:
            return {
                'success': False,
                'code': 'BAD_CERTIFICATE',
            }

        certificate = binascii.a2b_hex(certificate)

        files = view.get_files()

        if not files:
            return {
                'success': False,
                'code': 'MIN_1_FILE',
            }

        container = open_container(container_path, files)
        xml_sig = prepare_signature(certificate, container)

        # save intermediate signature XML to temp file
        with NamedTemporaryFile(delete=False) as f:
            f.write(xml_sig.dump())

        if not container.name:
            with NamedTemporaryFile(delete=False) as temp_container_file:
                container.save(temp_container_file.name)
        else:
            temp_container_file = None

        signed_digest = xml_sig.digest()
        digest_hash_b64 = binascii.b2a_base64(signed_digest).decode()

        update_esteid_session(
            request,
            signed_hash=digest_hash_b64,  # probably not needed, as we can take the hash from the signature XML
            temp_signature_file=f.name,
            temp_container_file=temp_container_file.name if temp_container_file else None,
        )

        logger.debug("Signature hash base64: %s", digest_hash_b64)

        return {
            'success': True,
            'digest': binascii.b2a_hex(signed_digest).decode(),
        }


class IdCardFinishAction(BaseAction):
    @classmethod
    def do_action(cls, view: "GenericDigitalSignViewMixin", params: dict = None, *, signature_value: str = None,
                  container_path: str = None):
        """
        The old API is to pass a dict of params (previously confusingly named `action_kwargs`),
        the keyword args are added here for clarity as to what the method accepts

        :param view:
        :param params:
        :param signature_value: a HEX encoded signature, as received from `hwcrypto.js`
        :return:
        """
        request = view.request
        session_data = get_esteid_session(request)
        if not session_data:
            return {
                'success': False,
                'code': 'NO_SESSION',
            }

        if signature_value is None:
            signature_value = params['signature_value']
            if not signature_value:
                return {
                    'success': False,
                    'code': 'BAD_SIGNATURE',
                }

        if container_path is None:
            container_path = params.get("container_path", "")

        logger.debug("Signature HEX: %s", signature_value)

        signed_hash_b64 = session_data['signed_hash']
        signature_value = binascii.a2b_hex(signature_value)

        temp_signature_file = session_data['temp_signature_file']
        temp_container_file = session_data['temp_container_file']

        with open(temp_signature_file, 'rb') as f:
            xml_sig = XmlSignature(f.read())
        os.remove(temp_signature_file)

        verify_cryptography(xml_sig.get_certificate_value(), signature_value, binascii.a2b_base64(signed_hash_b64), prehashed=True)

        if temp_container_file:
            # Load a partially prepared BDoc from a tempfile and clean it up
            container = BDoc2File(temp_container_file)
            os.remove(temp_container_file)
        else:
            container = BDoc2File(container_path)

        xml_sig.add_signature_value(signature_value)

        try:
            finalize_signature(xml_sig)
        except BDoc2Error:
            logger.exception("Signature confirmation service error")
            return {
                'success': False,
                'code': 'SERVICE_ERROR',
            }

        container.add_signature(xml_sig)

        return {
            'success': True,
            'container': container,
        }


class SignCompleteAction(BaseAction):
    @classmethod
    def do_action(cls, view, action_kwargs):
        service = view.get_service()

        return service.get_file_data(view.get_files())


class MobileIdSignAction(BaseAction):
    @classmethod
    def do_action(cls, view, action_kwargs):
        service = view.get_service()

        if not view.get_files():
            return {
                'success': False,
                'code': 'MIN_1_FILE',
            }

        # Create signed document
        service.create_signed_document()

        # add all files
        for file in view.get_files():
            service.add_datafile(file.file_name, file.mimetype, service.HASHCODE, file.size, file.content)

        try:
            # Call sign
            resp = service.mobile_sign(**action_kwargs)

        except DigiDocError as e:
            return {
                'success': False,
                'error_code': e.error_code,
                'message': service.ERROR_CODES.get(int(e.error_code), service.ERROR_CODES[100])
            }

        return {
            'success': True,
            'challenge': resp['ChallengeID'],
        }


class MobileIdStatusAction(BaseAction):
    @classmethod
    def do_action(cls, view, action_kwargs):
        service = view.get_service()

        status_info = service.get_status_info()

        # If error occured
        if status_info['StatusCode'] not in ['OUTSTANDING_TRANSACTION', 'SIGNATURE', 'REQUEST_OK']:
            return {
                'success': False,
                'code': status_info['StatusCode'],
                'message': service.MID_STATUS_ERROR_CODES[status_info['StatusCode']],
            }

        elif status_info['StatusCode'] == 'OUTSTANDING_TRANSACTION':
            return {
                'success': False,
                'pending': True,
            }

        else:
            return {
                'success': True,
            }


class MobileIdAuthenticateAction(BaseAction):
    @classmethod
    def do_action(cls, view, action_kwargs):
        service = view.get_service()

        try:
            # Call mobile_authenticate
            resp, challenge = service.mobile_authenticate(**action_kwargs)

            resp_challenge = binascii.unhexlify(resp['Challenge'])

            # Modify stored digidoc session
            view.set_digidoc_session(service.session_code)

            full_name = ' '.join([resp['UserGivenname'], resp['UserSurname']]).title()

            # Store Certificate owner information in session
            view.set_digidoc_session_data('mid_id_code', resp['UserIDCode'])
            view.set_digidoc_session_data('mid_firstname', resp['UserGivenname'])
            view.set_digidoc_session_data('mid_lastname', resp['UserSurname'])
            view.set_digidoc_session_data('mid_full_name', full_name)
            view.set_digidoc_session_data('mid_country', resp['UserCountry'])
            view.set_digidoc_session_data('mid_common_name', resp['UserCN'])

            # Store CertificateData in session (so we can verify later based on it)
            view.set_digidoc_session_data('mid_sp_challenge', challenge)
            view.set_digidoc_session_data('mid_resp_challenge', resp_challenge)
            view.set_digidoc_session_data('mid_certificate_data', resp['CertificateData'])

        except DigiDocError as e:
            return {
                'success': False,
                'error_code': e.error_code,
                'message': service.ERROR_CODES.get(int(e.error_code), service.ERROR_CODES[100])
            }

        return {
            'success': True,
            'challenge': resp['ChallengeID'],
            'challenge_raw': resp['Challenge'],
        }


class MobileIdAuthenticateStatusAction(BaseAction):
    @classmethod
    def do_action(cls, view, action_kwargs):
        service = view.get_service()

        try:
            status_code, signature = service.get_mobile_authenticate_status(**action_kwargs)

        except DigiDocError as e:
            return {
                'success': False,
                'pending': False,
                'code': e.error_code,
                'message': e.known_fault,
            }

        # FIXME: After signature verification is added, make sure to verify the signature here

        # If an error occurred
        if status_code not in ['OUTSTANDING_TRANSACTION', 'USER_AUTHENTICATED']:
            return {
                'success': False,
                'pending': False,
                'code': status_code,
                'message': service.MID_STATUS_ERROR_CODES[status_code],
            }

        if status_code == 'OUTSTANDING_TRANSACTION':
            return {
                'success': False,
                'pending': True,
                'code': status_code,
                'message': None,
            }

        # signature

        sp_challenge = view.get_digidoc_session_data('mid_sp_challenge')
        resp_challenge = view.get_digidoc_session_data('mid_resp_challenge')
        certificate_data = view.get_digidoc_session_data('mid_certificate_data')

        if not service.verify_mid_signature(certificate_data, sp_challenge, resp_challenge, signature):
            return {
                'success': False,
                'pending': False,
                'code': 'BAD_SIGNATURE',
                'message': service.MID_STATUS_ERROR_CODES['BAD_SIGNATURE'],
            }

        # USER_AUTHENTICATED
        return {
            'success': True,
            'pending': False,
            'code': status_code,
            'message': None,
        }
