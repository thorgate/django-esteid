# esteid signing

The idea: have a clear, extensible API that is easy to integrate.

Solution: One view, [Pluggable signers](#pluggable-signer)

## Contents
* [Quickstart](#quickstart)
* [Integration with projects](#integration-with-projects)
  * [Error handling and logging](#error-handling-and-logging)
  * [File types](#file-types)
* [Implementation details](#implementation-details)

## Quickstart

(Django without rest-framework)

```python
# views.py
from django.core.files.uploadedfile import UploadedFile
from django.views.generic import DetailView
from esteid.compat import container_info
from esteid.signing import Container, DataFile, SignViewDjangoMixin

class MyDocumentSignView(SignViewDjangoMixin, DetailView):
    def get_files_to_sign(self, *args, **kwargs):
        instance = self.get_object()
        return [
            DataFile("/path/to/document.doc", "application/ms-word-foo"),
            DataFile(instance.document, "application/openoffice-file-bar")
        ]

    def save_container(self, container: Container, *args, **kwargs):
        instance = self.get_object()
        # `container_info(container)` returns a dict with info about signature and files.
        # Be sure to call it before `container.finalize()`
        instance.container_info = container_info(container) 
        instance.container = UploadedFile(container.finalize(), "signed_document.doc", container.MIME_TYPE)
        instance.save()

# urls.py
from django.urls.conf import re_path

from esteid.signing import Signer
# Import all the necessary signers (a.k.a registration)
from esteid.idcard import IdCardSigner
from esteid.mobileid import MobileIdSigner
from esteid.smartid import SmartIdSigner
from .views import MyDocumentSignView


assert Signer.SIGNING_METHODS == {
    'idcard': IdCardSigner,
    'mobileid': MobileIdSigner,
    'smartid': SmartIdSigner,
}

urlpatterns = [
    re_path(rf"^/document/(?P<id>\w+)/sign/{method}/", 
            MyDocumentSignView.as_view(signing_method=method), 
            name=f"sign-{method}")
    for method in Signer.SIGNING_METHODS
]
```

For rest-framework, you only need to use a sibling `SignViewRestMixin` and `APIView`, see next section.

## Integration with projects

Integration is made easy by means of the view mixin class `SignViewMixin`.

For rest-framework, its derivative `SignViewRestMixin` implements the get, post, and patch handlers:
```python
from rest_framework.views import APIView
from esteid.signing import SignViewRestMixin

class YourSignView(SignViewRestMixin, APIView):
    ... 
``` 

For django without rest-framework, another derivative `SignViewDjangoMixin` can be used in a similar way:
```python
from django.views.generic import View
from esteid.signing import SignViewDjangoMixin

class YourSignView(SignViewDjangoMixin, View):
    ... 
``` 

The class `SignViewMixin` contains
three abstract methods for handling files/container to sign, and one method that
returns a success response once the signing process is complete.

In all of the methods below (both with and without rest-framework),
the current `request` object can be accessed via `self.request`, 
and the `*args, **kwargs` are forwarded directly from `get()` / `post()` / `patch()`. 

It's possible to call e.g. the view's `get_object()` if the operation requires calling it.

* on `POST`, the signing flow is started, and consumes either a list of files or a container
  that will be signed:

  * `get_container(self, *args, **kwargs)` --  if this method returns a path (`str`) 
    or a file handle to a BDOC/ASiC-E container,
    the files in this container will be signed.
    If the container contains signatures, they are not affected -- the newly obtained signature will be added;
  * `get_files_to_sign(self, *args, **kwargs)` -- if this method returns a list of files
    (see below for exact return types), these files will be packed into a new container
    that will be signed;
    
  **NOTE 1:** you need to implement only one of these methods. 

  **NOTE 2:** If `get_container()` is implemented, `get_files_to_sign()` is not used.
  
* on `GET` or `PATCH`, the signer instance polls the signature service (if necessary) and returns the current status.
  If the process is successfully completed, the following methods will be called:
  * `save_container(self, container, *args, **kwargs)` -- this method receives a temporary BDOC container file handle,
    and is expected to save it to a persistent store/django model;
  * `get_success_response(self, *args, **kwargs)` -- is expected to return a response which is meaningful
    for the application. By default, this just returns a JsonResponse of `{status: "success"}` with a status of 200.

**NOTE:** For security, if signing an existing container, the container is always copied to a temporary file.
Even though technically the container is only updated with a signature once, after signing is complete,
we need to insure that we are updating the exact same file that was there at the beginning of the process.
Also if container is stored in a remote storage, updating it in place can be impossible altogether.

### Error handling and logging

All exceptions that happen during signing are handled by the view mixin's method `handle_errors()`.

By default, all exceptions except for those listed below produce a non-descriptive JSON response with the HTTP status
of 500 _Internal server error_: 
```json
{
    "status": "error",
    "error": "Internal error", 
    "message": "Internal server error"
}
``` 
(the `message` may be translated.) 

This is done to avoid disclosure of particular implementation details and consequent attacks. 
Such errors are also logged.

Exceptions of types `Http404` and `rest_framework.exceptions.ValidationError` are propagated upstream to be handled
by Django and `rest_framework` natively, and not logged. 

Exceptions of `django.core.exceptions.ValidationError` type are converted into a JSON response 
with HTTP status of 409 (conflict) and a descriptive error message, and not logged. Below is a sample JSON response:
```json
{
    "status": "error",
    "error": "<< Exception class name >>", 
    "message": "<< Exception message >>"
}
``` 

Lastly, exceptions of type `EsteidError` and its derivatives produce an error response based on the exception
class's `default_message` and `status`. This can be altered by changing the `get_user_error()` method of the exception
class. These exceptions are logged, unless they are instances of `InvalidParameters`. 

If you need to add an exception with a descriptive error shown to the user, the preferred way is to subclass
`EsteidError`, or if it is related to user input, `InvalidParameters`, 
and add the corresponding `default_message` and `status` attributes.

The native Django and DRF `ValidationError`s can be used when the error is related to user input and not intended
for logging. Finally, `Http404` fits when the object to sign can not be found, and can be raised 
from the `get_container()` or `get_files_to_sign` methods.

### Handling of user cancellation of signing

When an additional action is necessary on user cancel, override the `handle_user_cancel` method of the signing view:

```python
class YourSignView(SignViewDjangoMixin, View):
    ...
    def handle_user_cancel(self):
        ...
``` 

### Signing party's eligibility

Technically it is possible for a signing party to sign a container multiple times. The XAdES standard doesn't seem to
impose any restrictions on that. Though as every signing transaction costs money (with SK.ee services) and 
to avoid issues in general, signing a container twice by the same person is disabled by default, except when debugging.

To allow multiple signatures by same party, set `ESTEID_ALLOW_ONE_PARTY_SIGN_TWICE` to `True` in django settings.

The eligibility check is performed by the view during the signature preparation phase,
in the `is_eligible_to_sign` method.
It accepts the container handle and the ID code of the signing party as returned by the `Signer` implementation
(for MobileID and SmartID, the ID code is entered by the user; for ID card, it is taken from the certificate).

The `is_eligible_to_sign` method of the view may be overridden to perform extra checks on the signing party. 
 

### File types

To generate a signature over files, it is necessary to know the file name, its mime type, and the content.
To simplify providing these data to `get_files_to_sign()`, a wrapper class [`DataFile`](./types.py) is included which
accepts a path to file, or a django `File` instance, and a `mime_type` argument, and deals with reading the file content
when appropriate.

## Implementation details

### Pluggable Signer

The outline of the flow implementation is the Dependency Inversion pattern: 
instead of the view explicitly calling an implementation, 
the view interacts with a Signer class, which loads a pluggable implementation
based on the method selected by user.

```
POST /path/to/sign/:method

{...params}
```
roughly translates to `Signer.start_session(method, session, init_params).prepare(container_path, files)`

```
GET /path/to/sign/:method
```
roughly translates to `Signer.load_session(method, request.session).finalize()`

```
PATCH /path/to/sign/:method

{...params}
```
roughly translates to `Signer.load_session(method, request.session).finalize(params)`


### Flow types (backend)

We don't cover the front end part here yet.

* the simplest flow: ID card
  * the `initial` request
    - In: the certificate obtained by JS from the browser plugin
    - Do: prepare the signature container
    - Out: a digest of the data to sign
  * the `final` request
    - In: signed digest (**NOTE:** this requires using the PATCH method to perform the HTTP request)
    - Do: finalize signature and container (OCSP, TSA)
    - Out: (can be a redirect to the container download view)
  * state between requests: the digest, temporary files
* the external service flow with status: Mobile ID
  * the `initial` request
    - In: Personal ID code, Phone number
    - Do: get user certificate from SK/MID; prepare the container; initiate the `sign` request to SK/MID
    - Out: signature verification code
  * the `status/final` request
    - In: -
    - Do: poll `status` at MID; if complete, finalize signature and container
    - Out: if not complete - pending, e.g. `202 Accepted`.
* the authentication+signing flow with external service (SmartID)
  * the `initial` request
    - In: Personal ID code
    - Do:  initiate the `authenticate` request to SK/SmartID
    - Out: authentication verification code
    - NOTE: at this point, it's early to prepare container.
  * the `status/final` request
    - In:
    - Do: determine what phase we're in
      - Phase 1 (Auth status): poll authentication status at SmartID
      - Phase 2 (Auth OK): receive user certificate from the SmartID service; prepare container; init `sign` request
      - Phase 3 (Sign status): poll signing status at SmartID
      - Phase 4 (Sign OK): finalize container
    - Out:
      - Phases 1, 2, 3: pending (`202 Accepted`)
      - Phase 2 specific: signature verification code
      - Phase 4: the regular return values on completion

So, even if the flows appear pretty different, they share a lot in common.

### Synchronous API flow

We only need one endpoint - using the `POST` method to initiate request (`initial`) and `GET` to fetch status (`status`);
on `cancel` the status handler is required to clean up the temporary files created on the initial call.

All the flows described above pass initialization parameters, if different, to the selected signing method on the `initial` endpoint call.

The `initial` request saves some data to the `request.session`, dependent on the signing method. Accordingly, this data is read
by the `status` request, and possibly also modified (SmartID phase 2 would add the signed data digest to the session).

The `status` request result can be a `202 Accepted` HTTP response, with an optional verification code to be displayed to the user
while initiating the `sign` phase.

If there was an `initial` request while signing process is still in progress (i.e. the session data is not empty), this should be
treated as an error, unless a certain timeout has elapsed since the ongoing process was initialized - this is necessary to prevent
cases when due to an error in handling, the session data was not cleaned up correctly. The duration of such a timeout can be no less than
two minutes, which includes the one-minute timeout for the user to confirm the signing process (enter PIN code) and a possible signing
process duration of 30 to 60 seconds. (References needed for the service's processing terms)

### Asynchronous flow

The synchronous API (MobileID and SmartID) is not very fit for servers with a large number of connections. Every status polling request
initiates an upstream request which is a long polling request and thus blocks the serving process typically for several seconds.

The solution would be to delegate the upstream service status polling to a Celery process and poll for the processing result
which could be saved to an intermediary DB table or cache.

Instead of polling, there can be a websocket control connection which receives the response from the Signer `status()` when a result is ready.

The benefit of such flow is that there is no need for sessions or temporary files; all data can be function-local and the whole process implemented
in one function (i.e. call `prepare` and then call `finalize` in a loop until it resolves).
