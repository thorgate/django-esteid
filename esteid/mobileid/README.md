# Signing with MobileID

Main documentation sources:
* API: https://github.com/SK-EID/MID


## Contents

* [Generic Action Sequence](#generic-action-sequence)
* [API Endpoints](#api-endpoints)
* [Calculate Verification Code](#calculate-verification-code) 


## Generic Action Sequence

1. Get user certificate from MobileID `/certificate` endpoint, passing it user's phone number and identity code.
    
1. Prepare the [XAdES signature structure](https://github.com/thorgate/pyasice) for signing, aka `XmlSignature`, 
   embedding into it the certificate obtained at the previous step. 
   The signed data is derived from this structure.
1. Display the verification code to the user, calculated based on the hash of the signed data.
1. Get the actual signature from the MobileID REST service.

    1. Start a signing session by sending a request to `/signature` endpoint, 
       complete with user's phone number and identity code,
       and the digest of the signed data.
      
    1. Poll the server for signing status, which returns the signature when successful.
    1. Use the certificate obtained at step 1, to verify the signature 

1. Finalize the `XmlSignature` structure with the received signature. 
   (See the [paragraph in SmartID](../smartid#finalize-the-xmlsignature-and-the-asic-e-container) for the details)
