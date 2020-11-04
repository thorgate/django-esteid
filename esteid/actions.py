import binascii
import logging
import typing
import warnings
from tempfile import NamedTemporaryFile

from django.conf import settings
from esteid_certificates import get_certificate

import pyasice
from pyasice import Container, finalize_signature, verify, XmlSignature

from esteid import constants
from esteid.exceptions import ActionInProgress, EsteidError, InvalidIdCode, UserNotRegistered
from esteid.mobileid.i18n import TranslatedMobileIDService
from esteid.smartid.i18n import TranslatedSmartIDService

from .session import delete_esteid_session, get_esteid_session, open_container, update_esteid_session
from .smartid.constants import Countries
from .util import id_code_ee_is_valid


if typing.TYPE_CHECKING:
    from .generic import GenericDigitalSignViewMixin

warnings.warn("The actions API is deprecated. Please use the new signing API", DeprecationWarning)

logger = logging.getLogger(__name__)

ESTEID_DEMO = getattr(settings, "ESTEID_DEMO", True)
ESTEID_COUNTRY = getattr(settings, "ESTEID_COUNTRY", Countries.ESTONIA)
ESTEID_USE_LT_TS = getattr(settings, "ESTEID_USE_LT_TS", True)

OCSP_URL = getattr(settings, "ESTEID_OCSP_URL", constants.OCSP_DEMO_URL if ESTEID_DEMO else constants.OCSP_LIVE_URL)
TSA_URL = getattr(settings, "ESTEID_TSA_URL", constants.TSA_DEMO_URL if ESTEID_DEMO else constants.TSA_LIVE_URL)


class BaseAction(object):
    @classmethod
    def do_action(cls, view: "GenericDigitalSignViewMixin", params):
        raise NotImplementedError


class NoAction(object):
    @classmethod
    def do_action(cls, view, params):
        return {"success": True}


class IdCardPrepareAction(BaseAction):
    @classmethod
    def do_action(cls, view: "GenericDigitalSignViewMixin", params: dict = None, *, certificate: str = None):
        """
        The old API is to pass a dict of params (previously confusingly named `action_kwargs`),
        the keyword args are added here for clarity as to what the method accepts

        :param view:
        :param params:
        :param certificate: HEX-encoded certificate from the ID card
        :return:
        """
        request = view.request
        delete_esteid_session(request)

        if not certificate:
            certificate = (params or {}).get("certificate")

        if not certificate:
            return {
                "success": False,
                "code": "BAD_CERTIFICATE",
            }

        certificate = binascii.a2b_hex(certificate)

        files = view.get_files()
        container_path = view.get_bdoc_container_file()

        if not (files or container_path):
            return {
                "success": False,
                "code": "MIN_1_FILE",
            }

        container = open_container(container_path, files)
        xml_sig = container.prepare_signature(certificate)

        # save intermediate signature XML to temp file
        with NamedTemporaryFile(delete=False) as temp_signature_file:
            temp_signature_file.write(xml_sig.dump())

        # always save container to a temp file
        with NamedTemporaryFile(mode="wb", delete=False) as temp_container_file:
            temp_container_file.write(container.finalize().getbuffer())

        signed_digest = xml_sig.digest()
        digest_hash_b64 = binascii.b2a_base64(signed_digest).decode()

        update_esteid_session(
            request,
            signed_hash=digest_hash_b64,  # we can take the hash from the signature XML, but it'd take time to compute
            temp_signature_file=temp_signature_file.name,
            temp_container_file=temp_container_file.name,
        )

        return {
            "success": True,
            "digest": binascii.b2a_hex(signed_digest).decode(),
        }


class IdCardFinishAction(BaseAction):
    @classmethod
    def do_action(cls, view: "GenericDigitalSignViewMixin", params: dict = None, *, signature_value: str = None):
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
                "success": False,
                "code": "NO_SESSION",
            }

        if signature_value is None:
            signature_value = (params or {}).get("signature_value")
            if not signature_value:
                return {
                    "success": False,
                    "code": "BAD_SIGNATURE",
                }

        logger.debug("Signature HEX: %s", signature_value)

        signed_hash_b64 = session_data["signed_hash"]
        signature_value = binascii.a2b_hex(signature_value)

        temp_signature_file = session_data["temp_signature_file"]
        temp_container_file = session_data["temp_container_file"]

        with open(temp_signature_file, "rb") as f:
            xml_sig = XmlSignature(f.read())

        # Load a partially prepared BDoc from a tempfile and clean it up
        container = Container.open(temp_container_file)

        # now we don't need the session anymore
        delete_esteid_session(request)

        verify(xml_sig.get_certificate_value(), signature_value, binascii.a2b_base64(signed_hash_b64), prehashed=True)

        xml_sig.set_signature_value(signature_value)
        issuer_cert = get_certificate(xml_sig.get_certificate_issuer_common_name())

        try:
            finalize_signature(xml_sig, issuer_cert, lt_ts=ESTEID_USE_LT_TS, ocsp_url=OCSP_URL, tsa_url=TSA_URL)
        except pyasice.Error:
            logger.exception("Signature confirmation service error")
            return {
                "success": False,
                "code": "SERVICE_ERROR",
            }

        container.add_signature(xml_sig)

        return {
            "success": True,
            "container": container,
        }


class SignCompleteAction(BaseAction):
    @classmethod
    def do_action(cls, view, action_kwargs):
        """Return the signed container"""
        raise NotImplementedError


class MobileIdSignAction(BaseAction):
    @classmethod
    def do_action(
        cls,
        view: "GenericDigitalSignViewMixin",
        params: dict = None,
        *,
        phone_number: str = None,
        id_code: str = None,
        language: str = None,
    ):
        """
        The old API is to pass a dict of params (previously confusingly named `action_kwargs`),
        the keyword args are added here for clarity as to what the method accepts

        :param view:
        :param params:
        :param phone_number:
        :param id_code:
        :param language:
        :return:
        """
        request = view.request
        delete_esteid_session(request)

        if not phone_number:
            phone_number = params["phone_number"]
        if not id_code:
            id_code = params["id_code"]

        if not (phone_number and id_code):
            return {
                "success": False,
                "code": "BAD_PARAMS",
            }

        # NOTE: since EE and LT id codes use the same format, we are using the same function.
        if not id_code_ee_is_valid(id_code):
            return {
                "success": False,
                "code": "INVALID_ID_CODE",
            }

        files = view.get_files()
        container_path = view.get_bdoc_container_file()

        if not (files or container_path):
            return {
                "success": False,
                "code": "MIN_1_FILE",
            }

        service = TranslatedMobileIDService.get_instance()

        try:
            certificate = service.get_certificate(id_code, phone_number)
        except UserNotRegistered:
            return {
                "success": False,
                "code": "NOT_A_MOBILEID_USER",
            }

        container = open_container(container_path, files)
        xml_sig = container.prepare_signature(certificate)

        # save intermediate signature XML to temp file
        with NamedTemporaryFile(delete=False) as temp_signature_file:
            temp_signature_file.write(xml_sig.dump())

        # always save container to a temp file
        with NamedTemporaryFile(mode="wb", delete=False) as temp_container_file:
            temp_container_file.write(container.finalize().getbuffer())

        try:
            sign_session = service.sign(id_code, phone_number, xml_sig.signed_data(), language=language)
        except EsteidError:
            return {
                "success": False,
                "code": "SIGN_SESSION_FAILED",
            }

        signed_digest = sign_session.digest
        digest_hash_b64 = binascii.b2a_base64(signed_digest).decode()

        update_esteid_session(
            request,
            session_id=sign_session.session_id,
            digest_b64=digest_hash_b64,
            temp_signature_file=temp_signature_file.name,
            temp_container_file=temp_container_file.name,
        )

        return {
            "success": True,
            "challenge": sign_session.verification_code,
            "verification_code": sign_session.verification_code,
        }


class MobileIdStatusAction(BaseAction):
    @classmethod
    def do_action(cls, view: "GenericDigitalSignViewMixin", params: dict = None):

        request = view.request
        session_data = get_esteid_session(request)
        if not session_data:
            return {
                "success": False,
                "code": "NO_SESSION",
            }

        session_id = session_data["session_id"]
        signed_digest = session_data["digest_b64"]
        temp_signature_file = session_data["temp_signature_file"]
        temp_container_file = session_data["temp_container_file"]

        with open(temp_signature_file, "rb") as f:
            xml_sig = XmlSignature(f.read())

        # Load a partially prepared BDoc from a tempfile and clean it up
        container = Container.open(temp_container_file)

        service = TranslatedMobileIDService.get_instance()
        try:
            status = service.sign_status(
                session_id, xml_sig.get_certificate_value(), binascii.a2b_base64(signed_digest)
            )
        except ActionInProgress:
            #  when there is an `ActionInProgress` exception, we shouldn't delete the session.
            return {
                "success": False,
                "pending": True,
            }
        except Exception:
            # NOTE: we could pick some exceptions that don't require cleanup,
            # but this also requires support from the party that polls this action.
            # Most likely the whole process would need to be restarted anyway
            delete_esteid_session(request)
            raise

        # now we don't need the session anymore
        delete_esteid_session(request)

        xml_sig.set_signature_value(status.signature)

        issuer_cert = get_certificate(xml_sig.get_certificate_issuer_common_name())

        try:
            finalize_signature(xml_sig, issuer_cert, lt_ts=ESTEID_USE_LT_TS, ocsp_url=OCSP_URL, tsa_url=TSA_URL)
        except pyasice.Error:
            logger.exception("Signature confirmation service error")
            return {
                "success": False,
                "code": "SERVICE_ERROR",
            }

        container.add_signature(xml_sig)

        return {
            "success": True,
            "container": container,
        }


class SmartIdSignAction(BaseAction):
    @classmethod
    def do_action(
        cls,
        view: "GenericDigitalSignViewMixin",
        params: dict = None,
        *,
        id_code: str = None,
        country: str = None,
        language: str = None,
    ):
        """
        The old API is to pass a dict of params (previously confusingly named `action_kwargs`),
        the keyword args are added here for clarity as to what the method accepts
        """
        request = view.request
        delete_esteid_session(request)

        params = params or {}
        if not id_code:
            id_code = params.get("id_code")

        if not country:
            country = params.get("country") or ESTEID_COUNTRY

        files = view.get_files()
        container_path = view.get_bdoc_container_file()

        if not (files or container_path):
            return {
                "success": False,
                "code": "MIN_1_FILE",
            }

        service = TranslatedSmartIDService.get_instance()

        try:
            auth_result = service.authenticate(id_code, country)
        except InvalidIdCode:
            return {
                "success": False,
                "code": "INVALID_ID_CODE",
            }
        except UserNotRegistered:
            return {
                "success": False,
                "code": "NOT_A_SMARTID_USER",
            }
        except EsteidError:
            logger.exception("An error occurred during SmartID authentication")
            raise

        container = open_container(container_path, files)
        # always save container to a temp file
        with NamedTemporaryFile(mode="wb", delete=False) as temp_container_file:
            temp_container_file.write(container.finalize().getbuffer())

        update_esteid_session(
            request,
            session_id=auth_result.session_id,
            digest_b64=binascii.b2a_base64(auth_result.hash_value).decode(),
            temp_container_file=temp_container_file.name,
            phase="auth",
        )

        return {
            "success": True,
            "verification_code": auth_result.verification_code,
        }


class SmartIdStatusAction(BaseAction):
    @classmethod
    def auth_status_and_start_sign(cls, request, session_data):
        logger.debug("SmartID auth_status_and_start_sign")
        session_id = session_data["session_id"]
        signed_digest = session_data["digest_b64"]

        service = TranslatedSmartIDService.get_instance()

        # this may raise ActionInProgress
        result = service.status(session_id, binascii.a2b_base64(signed_digest), timeout=1000)

        certificate, _ = service.select_signing_certificate(document_number=result.document_number)

        temp_container_file_name = session_data["temp_container_file"]

        container = Container.open(temp_container_file_name)
        xml_sig = container.prepare_signature(certificate)

        sign_result = service.sign_by_document_number(result.document_number, xml_sig.signed_data())

        # save intermediate signature XML to temp file
        with NamedTemporaryFile(delete=False) as temp_signature_file:
            temp_signature_file.write(xml_sig.dump())

        # save container to the same temp file
        container.save(temp_container_file_name)

        signed_digest = sign_result.digest
        digest_hash_b64 = binascii.b2a_base64(signed_digest).decode()

        update_esteid_session(
            request,
            session_id=sign_result.session_id,
            digest_b64=digest_hash_b64,
            temp_signature_file=temp_signature_file.name,
            temp_container_file=temp_container_file_name,
            phase="sign",
        )
        return {
            "success": True,
            "verification_code": sign_result.verification_code,
        }

    @classmethod
    def do_action(cls, view: "GenericDigitalSignViewMixin", params: dict = None):
        request = view.request
        session_data = get_esteid_session(request)
        if not session_data:
            return {
                "success": False,
                "code": "NO_SESSION",
            }

        phase = session_data.get("phase")
        if phase == "auth":
            try:
                return cls.auth_status_and_start_sign(request, session_data)
            except ActionInProgress:
                return {
                    "success": False,
                    "pending": True,
                }
            except Exception:
                logger.exception("Failed to select signing certificate with Smart ID")
                # NOTE: we could pick some exceptions that don't require cleanup,
                # but this also requires support from the party that polls this action.
                # Most likely the whole process would need to be restarted anyway
                delete_esteid_session(request)
                raise
        elif phase != "sign":
            return {
                "success": False,
                "code": "NO_SESSION",
            }

        # Continue with signing - poll status and finalize
        logger.debug("SmartID: polling status of signing")

        session_id = session_data["session_id"]
        signed_digest = session_data["digest_b64"]
        temp_signature_file = session_data["temp_signature_file"]
        temp_container_file = session_data["temp_container_file"]

        service = TranslatedSmartIDService.get_instance()
        try:
            status = service.sign_status(session_id, binascii.a2b_base64(signed_digest))
        except ActionInProgress:
            # Do not delete session here.
            return {
                "success": False,
                "pending": True,
            }
        except Exception:
            logger.exception("Failed to get signing status from Smart ID service")
            # NOTE: we could pick some exceptions that don't require cleanup,
            # but this also requires support from the party that polls this action.
            # Most likely the whole process would need to be restarted anyway
            delete_esteid_session(request)
            raise

        logger.debug("SmartID Signing complete")

        with open(temp_signature_file, "rb") as f:
            xml_sig = XmlSignature(f.read())

        # Load a partially prepared BDoc from a tempfile and clean it up
        container = Container.open(temp_container_file)

        # now we don't need the session anymore
        delete_esteid_session(request)

        xml_sig.set_signature_value(status.signature)

        issuer_cert = get_certificate(xml_sig.get_certificate_issuer_common_name())

        try:
            finalize_signature(xml_sig, issuer_cert, lt_ts=ESTEID_USE_LT_TS, ocsp_url=OCSP_URL, tsa_url=TSA_URL)
        except pyasice.Error:
            logger.exception("Signature confirmation service error")
            return {
                "success": False,
                "code": "SERVICE_ERROR",
            }

        container.add_signature(xml_sig)

        return {
            "success": True,
            "container": container,
        }
