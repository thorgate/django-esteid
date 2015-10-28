from . import config
from .actions import (IdCardPrepareAction, IdCardFinishAction, SignCompleteAction, MobileIdSignAction, MobileIdStatusAction, BaseAction,
                      MobileIdAuthenticateAction, MobileIdAuthenticateStatusAction)
from .digidocservice.service import DigiDocService, DigiDocError
from .response import JSONResponse


class GenericDigitalSignViewMixin(object):
    def get_files(self):
        """ This should be implemented on view level, and should return a list
            of files that should be digitally signed
        """
        return []

    def start_digidoc_session(self, session_code):
        """ Stores the new session token so it is remembered across requests.

        """

        self.request.session['__ddoc_session'] = session_code

    def get_digidoc_session(self):
        """ This method returns the active digidoc session
            associated with the active request.

            DigiDocService session is stored in request.session['__ddoc_session']
        """

        try:
            return self.request.session['__ddoc_session']

        except KeyError:
            return None

    def destroy_digidoc_session(self):
        """ Closes DigiDocService session and clears request.session['__ddoc_session']
        """

        try:
            session = self.request.session['__ddoc_session']

            if session:
                try:
                    service = self.flat_service()
                    service.session_code = session
                    service.close_session()

                except DigiDocError:
                    pass

            del self.request.session['__ddoc_session']

        except KeyError:
            pass

    def flat_service(self):
        return DigiDocService(
            service_name=config.service_name(),
            client_type=config.client_type(),
            mobile_message=config.mobile_message(),
        )

    def start_session_kwargs(self):
        return {
            'b_hold_session': True,
        }

    def get_service(self):
        if hasattr(self, 'stored_service'):
            return self.stored_service

        service = self.flat_service()
        session = self.get_digidoc_session()

        if session:
            service.session_code = session

        else:
            if service.start_session(**self.start_session_kwargs()):
                self.start_digidoc_session(service.session_code)

        setattr(self, 'stored_service', service)
        return service


class BaseDigitalSignViewMixin(GenericDigitalSignViewMixin):
    CATCH_POST = True
    ACTION_CLASS = None

    def post(self, request, *args, **kwargs):
        if self.CATCH_POST:
            return JSONResponse(self.do_action(*args, **kwargs))

        return super().post(request, *args, **kwargs)

    def build_action_kwargs(self):
        return {}

    def do_action(self, *args, **kwargs):
        if not self.ACTION_CLASS or not issubclass(self.ACTION_CLASS, BaseAction):
            raise NotImplementedError

        return self.ACTION_CLASS.do_action(self, action_kwargs=self.build_action_kwargs())


class IdCardPrepareViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = IdCardPrepareAction


class IdCardFinishViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = IdCardFinishAction


class DigidocCompleteViewMixin(BaseDigitalSignViewMixin):
    """ This action gets the signed document from this DigiDocService session
        and then closes it. It's up to the user what he/she wants to do with it.
    """
    CATCH_POST = False
    ACTION_CLASS = SignCompleteAction


class MobileIdSignViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = MobileIdSignAction


class MobileIdStatusViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = MobileIdStatusAction


class MobileIdAuthenticateViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = MobileIdAuthenticateAction


class MobileIdAuthenticateStatusViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = MobileIdAuthenticateStatusAction
