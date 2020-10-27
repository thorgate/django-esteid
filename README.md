# django-esteid

[![pypi Status](https://badge.fury.io/py/django-esteid.png)](https://badge.fury.io/py/django-esteid)
[![Build Status](https://travis-ci.org/thorgate/django-esteid.svg?branch=master)](https://travis-ci.org/thorgate/django-esteid)

Django-esteid is a package that provides Esteid based authentication for your Django applications.

## Quickstart

Install `django-esteid`:

    pip install django-esteid

Add `esteid` to installed apps:

    INSTALLED_APPS = [
        # ...
        'esteid',
        # ...
    ]

Then use it in a project:

    import esteid

### SmartID

Detailed docs are [here](esteid/smartid/README.md).

### MobileID

Detailed docs are [here](esteid/mobileid/README.md).

### Id Card

Detailed docs are [here](esteid/idcard/README.md).


## Testing

There is a possibility to test the signing flow with ID card, SmartID 
and Mobile ID (the demo services) with the test views coming with the library.

**NOTE:** you may not be able to use the live Esteid services even with live credentials.
The live services keep an IP address whitelist 
which only contains IP addresses as specified in customer's contract.

To run the django-esteid test server with the test views, 
* install the virtual environment if not installed yet,
* run `./manage.py migrate` to create the SQLite DB for sessions,
* run `./manage.py runserver 8765`, where 8765 is a port of your liking

then visit the URL http://localhost:8765/ and follow the instructions on that page.

### Mobile ID

To test Mobile ID signing, you will need [test phone numbers and ID codes](https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO).

You can not use real phone numbers or ID codes with the demo service.

### SmartID

To test signing with SmartID, yoy can use [the test ID codes](https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters).
 
You can also register a demo SmartID account and use a demo SmartID app to enter the PINs; please visit the
[demo SmartID portal](https://sid.demo.sk.ee/portal/login) for the details. 

### ID card

ID card signing requires SSL to work, even in a testing enviorment.  
Note that the signature will not be valid neither with the real certificates, nor with the test ones. 

To perform signing with ID card, you would need the `chrome-token-signing` package installed.
`apt-get install chrome-token-signing`

#### Testing with ssl
 
You can make your webserver https enabled by first creating the cert using openssl.
```
openssl req -x509 -out localhost.crt -keyout localhost.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=localhost' -extensions EXT -config <( \
   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
```
Then start the webserver with runsslserver, then you can connect to `https://127.0.0.1:8000`

`python manage.py runsslserver 127.0.0.1:8000 --certificate localhost.crt --key localhost.key`

Note that the cert is self-signed, so you will need to create a security exception.

#### ngrok
If you don't want to use a self-signed cert you can route the test site through HTTPS with [ngrok](https://ngrok.com/). 

With `ngrok` installed, and the `./manage.py runserver 8765` started, run
`ngrok http http://127.0.0.1:8765` and it will create a tunnel with an HTTPS URL for your local site.

### Verify demo containers with digidoc-tool

It's possible to use the command line utility `digidoc-tool` 
from the [libdigidocpp library](https://github.com/open-eid/libdigidocpp/)
to verify containers with signatures created by demo services:
```
digidoc-tool open --tslurl=https://open-eid.github.io/test-TL/tl-mp-test-EE.xml --tslcert=trusted-test-tsl.crt <file>
```
Instructions on setting up the environment 
[can be found here](https://github.com/open-eid/libdigidocpp/wiki/Using-test-TSL-lists#digidoc-toolexe-utility-program).
