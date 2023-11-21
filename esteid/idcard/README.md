# ID Card Signing and Authentication

## Signing with ID Card

### Process outline

1. Fetch the user certificate from the ID Card

   On the frontend, query the the `web-eid.js` API that interacts with the ID card,
   to obtain the certificate that would be required for the initial XAdEs structure.  

1. Initialization request to the backend 

   The backend creates a BDoc (Asic-E) container with files to be signed (or takes an existing container). 
   The files' digests, together with the user certificate received from the ID card on step 1,
   are embedded into a XAdEs structure which constitutes the value that is to be signed.
   This value is returned to the frontend.
   
   The container (if it is newly created), and the XAdEs structure, are stored in temporary files.
   
1. Signature generation (frontend) 

   The frontend passes the value for signing to the `web-eid.js` API, 
   and passes on the obtained signature to the backend. 
   
1. Finalization of the container (backend) 

   The backend picks up the XAdEs structure and container 
   from the temporary files created on step 2, 
   inserts the received signature into the XAdEs structure and packs it into the container.
  
   The container is saved to a desired location, and the temporary files are cleaned up.
   

### Potential issues

#### Blocking on data processing

Since the process no longer involves an external service, but the files to be signed can potentially
be hefty, the process can block for a longer time while calculating hashes and (re-)packing the files
into the container. (At the same time, employing an external service, it would block on a network read, 
since the API is synchronous.)

#### Compatibility

Since the previous service-based action implementation provided for a very long inheritance tree
of action classes which all override the `do_action` method in some way but still make a call to a
non-existent `service`, it's advised that all those "actions" be scrapped in favor of a simpler API. 

## Authentication with ID Card

1. User clicks on a link to start the authentication process
2. The backend generates a random nonce, stores it in the session and then returns it to the frontend
    as a base64 string.
3. The string is passed to web-eid.js API, which initiates the authentication process.
4. web-eid.js combines the nonce with the site origin URl and takes hashes of both. The hashes are
    then concatenated and hashed once more.
   - Warning: Web-eid does not decode the base64 nonce here and uses it as is. This may be a bug in web-eid.js, link to issue below. 
5. User is prompted for a PIN code.
6. The combined hash is signed with the ID card and returned to the frontend.
7. The web-eid.js API passes the signature, unverified certificate and some metadata to the backend.
8. The backend verifies that the signature is valid by computing the hash the same way and then uses
    the public key of the signer to verify it.
9. The backend calls OCSP service to verify that the certificate is valid.
10. The backend stores user information in the session (and usually logs people in).

References:

- https://github.com/web-eid/
- https://github.com/web-eid/web-eid-system-architecture-doc
- https://github.com/web-eid/web-eid-system-architecture-doc/issues/5
