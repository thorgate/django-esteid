# ID Card Signing and Authentication

## Signing with ID Card

### Process outline

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

### Process Outline

The request to the client to enter PIN is initialized by a specifically configured web server,
with an option similar to `ssl_verify_client` on nginx.

On nginx, it is only possible to protect an entire `server` section with this option, which means that
in order to keep the site generally accessible to unauthenticated clients we need to set up a separate domain
that would handle the ID card authentication process, and pass the client authentication data to the primary site
via session or other means.

There is a caveat: browsers keep a certificate in cache for an unspecified period of time,
and a new request for PIN may not be triggered even once the authenticated ID card is removed or replaced.
This is not possible to control by the web server. 
One way around it is to use unique subdomains for every new authentication request.

Let's describe the key points of the ID card authentication process, based on the usual routine common for
SmartID and MobileID. 

The process thus should consist of the following steps:
* While visiting the site (assuming `example.com` for this matter), the user clicks on a link to start the authentication process;
* Instead of issuing a _start_ request to the backend (as in the usual routine), 
  or a `hwcrypto` library call (as in the process of signing with ID card), the user is taken to a specifically configured
  domain (e.g. `UNIQUE.auth.example.com`) where they are asked for the ID Card's PIN code and 
  proceed to allow the site to access the certificate;
* the certificate is validated via OCSP (see below as to why);
* the certificate or data obtained from it is saved to the session;
* user is redirected to the protected page on the `example.com` site.

The process above is by and large impractical. One improvement that could be made to it is to use an iframe instead of
a redirect; this provides for a smooth procedure, but additional measures must be taken, such as adding appropriate
`Content-Security-Policy` headers.

Another alternative, in case there is no need to use user's authentication data on the frontend,
is to direct the client to a separate domain as mentioned above, which would redirect back on success or else
to an error page.

### Notes

* With an AJAX / `fetch` request, the browser (most likely the `chrome-token-signing` plugin) is not able to process
  the response from the `auth.DOMAIN` server and shows an alert "Technical error".

* There is apparently no way to access content inside the iframe from the parent window, 
  even with CORS headers set. The only feasible way is to send `postMessage` to the parent window.

* The ID card authentication certificate is cached by the browser, 
  and there is apparently no way to manage or work around this cache from the application.
  The multi-domain approach (i.e. each new authentication happens on a different domain) didn't help.

* User certificate validation is done via OCSP in the django application, rather than using 
  Certificate Revocation Lists (CRLs) on the nginx, because of a problem with one of the root certificates: 
  http://mailman.nginx.org/pipermail/nginx-devel/2017-March/009609.html, https://trac.nginx.org/nginx/ticket/1094.
