# Signing with SmartID

Main documentation sources:
* Technical overview: https://github.com/SK-EID/smart-id-documentation/wiki/Technical-overview
* API: https://github.com/SK-EID/smart-id-documentation

## Contents

* [Authentication](#authentication)
* [Signing](#signing)
* [API Endpoints](#api-endpoints)
* [Calculate Verification Code](#calculate-verification-code) 

## Authentication

Generic action sequence:

1. Call the SmartID `start authentication session` endpoint, with a randomly generated _hash value_. 

    API endpoint docs: https://github.com/SK-EID/smart-id-documentation#239-authentication-session

    The endpoint returns a _session identifier_

1. Using the same _hash value_, calculate and display to the user a verification code.
1. Repeatedly poll the SmartID `session status` endpoint, passing the session identifier 
   obtained at step 1 as a parameter, until the endpoint returns a response with status `COMPLETE`.
1. If the previous step's response was not an error, there is a user certificate attached to it. 
   The user authentication information is obtained from the certificate.   


## Signing

Generic action sequence:

1. Get user's signing certificate from SmartID (aka certificate selection).

   This endpoint also returns document number for later use. 

1. Prepare the [XAdES signature structure](https://github.com/thorgate/pyasice) for signing, aka `XmlSignature`. 
1. Get the actual signature from the SmartID service.

    1. Start a signing session using the document number and certificate from the
        certificate selection response.
    1. Present a Verification Code in the response, which user is expected to see on his device before entering PIN2
    1. Poll the server for signing status, which returns the signature when successful. 

1. ##### Finalize the XmlSignature and the ASiC-E container
    
    1. Update the `XmlSignature` structure with the received signature.
        1. Ensure _Long-Term_ signature validity for compliance with XAdES-LT profile (as per the [BDOC v2.1 spec](https://www.id.ee/public/bdoc-spec212-eng.pdf))
        1. Perform an OCSP request for user's certificate validity confirmation, and embed the response in the `XmlSignature`.
            It's possible to stop at this point but only if the OCSP service is qualified for a Time-Mark response 
            (for a so-called XAdES-LT-TM signature), and apparently the one we use is not qualified.
        1. Perform a TimeStamp request -- a feature of an XAdES-LT-TS document 
        1. Embed the received responses in the `XmlSignature` object.
    1. Build a new BDOC container, or update an existing one, with the resulting `XmlSignature` XML content.
 

## API Endpoints


Initialize the signing session: 
https://github.com/SK-EID/smart-id-documentation#2310-signing-session

Poll session status:
https://github.com/SK-EID/smart-id-documentation#2311-session-status

Successful result structure:

```json
{
    "signature": {
        "value": "B+C9XVjIAZnCHH9vfBSv...",
        "algorithm": "sha512WithRSAEncryption"
    },
    "cert": {
        "value": "B+C9XVjIAZnCHH9vfBSv...",
        "assuranceLevel": "http://eidas.europa.eu/LoA/substantial",
		"certificateLevel": "QUALIFIED"
    }
}
```

## Calculate Verification Code

```python
from esteid.smartid.utils import get_verification_code
get_verification_code(signed_data) 
```

## Open Questions

* How/where to get an OCSP TM qualified response? The demo OCSP service doesn't return one.
