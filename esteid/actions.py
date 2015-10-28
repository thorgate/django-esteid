from .digidocservice.service import DigiDocError


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

        # Call sign
        try:
            response = service.prepare_signature(**action_kwargs)
            response['success'] = True
            return response

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
            return {
                'success': service.finalize_signature(**action_kwargs),
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
            resp = service.mobile_authenticate(**action_kwargs)

        except DigiDocError as e:
            return {
                'success': False,
                'error_code': e.error_code,
                'message': service.ERROR_CODES.get(int(e.error_code), service.ERROR_CODES[100])
            }

        view.request.session['mid_person_code'] = resp['UserIDCode']
        view.request.session['mid_common_name'] = resp['UserCN']

        return {
            'success': True,
            'challenge': resp['ChallengeID'],
        }


class MobileIdAuthenticateStatusAction(BaseAction):
    @classmethod
    def do_action(cls, view, action_kwargs):
        service = view.get_service()

        status_info = service.get_mobile_authenticate_status()

        # If error occured
        if status_info['Status'] not in ['OUTSTANDING_TRANSACTION', 'USER_AUTHENTICATED', 'REQUEST_OK']:
            return {
                'success': False,
                'code': status_info['StatusCode'],
                'message': service.MID_STATUS_ERROR_CODES[status_info['StatusCode']],
            }

        elif status_info['Status'] == 'OUTSTANDING_TRANSACTION':
            return {
                'success': False,
                'pending': True,
            }

        else:
            return {
                'success': True,
            }
