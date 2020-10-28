# Signing with SmartID

Main documentation sources:
* Technical overview: https://github.com/SK-EID/smart-id-documentation/wiki/Technical-overview
* API: https://github.com/SK-EID/smart-id-documentation

**Note:***

Currently containers with a SmartID-generated signature are not compatible with MobileID/ID-Card.
This means, such a signature is valid, but adding another signature to the same container
by means of MobileID/ID-Card DigiDoc Service API will fail. 

This is the limitation of DigiDoc Service (which uses old versions of 
respective libraries) and can not be resolved except by moving to the new REST API for MobileID. 

Adding a SmartID signature to a container with a previously generated SmartID signature, 
as well as a MobileID/ID-Card generated one, works without restrictions.

(Same note is included in the [top level readme](../../README.md).)

## Contents

* [Generic Action Sequence](#generic-action-sequence)
* [API Endpoints](#api-endpoints)
* [Calculate Verification Code](#calculate-verification-code) 


## Generic Action Sequence

1. Authenticate user in SmartID.
    This gives us the user's document number.
    
    1. Initial Request:
        * INPUT: user's ID code.
        * Initialize an authentication session. 
        * OUTPUT: Present a Verification Code in the response, which user is expected to see on his device before entering PIN1 
    1. Poll the server for authentication status 
    
1. Get user's signing certificate from SmartID (aka certificate selection).
    This should be ready in two requests, one is again a session initialization, the second one is the result. 

1. Prepare the [XAdES signature structure](https://github.com/thorgate/pyasice) for signing, aka `XmlSignature`. 
1. Get the actual signature from the SmartID service.

    1. Start a signing session using the document number from the authentication response and the certificate from the
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
https://github.com/SK-EID/smart-id-documentation#45-signing-session

Poll session status:
https://github.com/SK-EID/smart-id-documentation#46-session-status

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
