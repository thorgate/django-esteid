import binascii

from .digidocservice.service import DigiDocError, DigiDocNotOk


class BaseAction(object):
    @classmethod
    def do_action(cls, view, action_kwargs):
        raise NotImplementedError


class NoAction(object):
    @classmethod
    def do_action(cls, view, action_kwargs):
        return {'success': True}


class IdCardPrepareAction(BaseAction):
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

        # Call prepare_signature
        try:
            response = service.prepare_signature(**action_kwargs)
            response['success'] = True
            return response

        except DigiDocNotOk as e:
            return {
                'success': False,
                'error_code': e.code,
                'message': str(e),
            }

        except DigiDocError as e:
            return {
                'success': False,
                'error_code': e.error_code,
                'message': service.ERROR_CODES.get(int(e.error_code), service.ERROR_CODES[100])
            }


class IdCardFinishAction(BaseAction):
    @classmethod
    def do_action(cls, view, action_kwargs):
        service = view.get_service()

        try:
            # Should we also pass back the signed_doc_info (?)
            service.finalize_signature(**action_kwargs)

            return {
                'success': True,
            }

        except DigiDocNotOk as e:
            return {
                'success': False,
                'error_code': e.code,
                'message': str(e),
            }

        except DigiDocError as e:
            return {
                'success': False,
                'error_code': e.error_code,
                'message': service.ERROR_CODES.get(int(e.error_code), service.ERROR_CODES[100])
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
