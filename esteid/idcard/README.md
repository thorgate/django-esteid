# Signing with ID Card

## Process outline

1. Fetch the user certificate from the ID Card

   On the frontend, query the the `hwcrypto.js` API that interacts with the ID card,
   to obtain the certificate that would be required for the initial XAdEs structure.  

1. Initialization request to the backend 

   The backend creates a BDoc (Asic-E) container with files to be signed (or takes an existing container). 
   The files' digests, together with the user certificate received from the ID card on step 1,
   are embedded into a XAdEs structure which constitutes the value that is to be signed.
   This value is returned to the frontend.
   
   The container (if it is newly created), and the XAdEs structure, are stored in temporary files.
   
1. Signature generation (frontend) 

   The frontend passes the value for signing to the `hwcrypto.js` API, 
   and passes on the obtained signature to the backend. 
   
1. Finalization of the container (backend) 

   The backend picks up the XAdEs structure and container 
   from the temporary files created on step 2, 
   inserts the received signature into the XAdEs structure and packs it into the container.
  
   The container is saved to a desired location, and the temporary files are cleaned up.
   

## Potential issues

### Blocking on data processing

Since the process no longer involves an external service, but the files to be signed can potentially
be hefty, the process can block for a longer time while calculating hashes and (re-)packing the files
into the container. (At the same time, employing an external service, it would block on a network read, 
since the API is synchronous.)

### Compatibility

Since the previous service-based action implementation provided for a very long inheritance tree
of action classes which all override the `do_action` method in some way but still make a call to a
non-existent `service`, it's advised that all those "actions" be scrapped in favor of a simpler API. 

## The suggested API

TBD
