# ID-Card Authentication Test App with Nginx

Prerequisites: docker, docker-compose.

Sources of insight:
* Nginx SSL module docs: http://nginx.org/en/docs/http/ngx_http_ssl_module.html
* [Esteid own guide](https://eid.eesti.ee/index.php/Authenticating_in_web_applications)
* https://fardog.io/blog/2017/12/30/client-side-certificate-authentication-with-nginx/
* https://www.ssltrust.com.au/help/setup-guides/client-certificate-authentication

## Setup

These steps have been already done, and the necessary files are in place. 
The instructions here would be helpful though, if one would like to set up a new project. 

Also, some of these files (certificates) need periodic refresh. 

### Generate SSL certificate

For ID card auth to work, it is necessary to establish SSL connections. 

Assuming the server listening to https://localhost:8443, we will also need
a subdomain that is configured to negotiate the ID card certificate with the browser. 
It's easily achieved with the `xip.io` trick, thus we will provide 
a self-signed SSL certificate for https://127.0.0.1.xip.io and https://auth.127.0.0.1.xip.io domains.

Execute the following command in the [`./etc.nginx/ssl`](./etc.nginx/ssl) subdirectory:

```shell
DOMAIN=127.0.0.1.xip.io
openssl req -x509 -days 3650 -out cert.crt -keyout cert.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=$DOMAIN" -extensions EXT -config <( \
   printf "[dn]\nCN=$DOMAIN\n[req]\ndistinguished_name=dn\n[EXT]\nsubjectAltName=DNS:$DOMAIN,DNS:auth.$DOMAIN\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
```

(Though, indeed, the domain name in the cert doesn't matter because either way it will be necessary to add
a security exception)

### Get SK certs and place them in one file

A list of required certificates and links to the certificate files can be found on this page:
https://www.skidsolutions.eu/en/repository/certs/

Out of certificates listed, only those marked as "Valid" are necessary.

Execute the following command in the current directory:

```shell
curl -sSL \
 https://www.sk.ee/upload/files/EE_Certification_Centre_Root_CA.pem.crt \
 https://c.sk.ee/EE-GovCA2018.pem.crt \
 https://c.sk.ee/esteid2018.pem.crt \
 https://www.sk.ee/upload/files/ESTEID-SK_2011.pem.crt \
 https://www.skidsolutions.eu/upload/files/ESTEID-SK_2015.pem.crt \
 https://www.sk.ee/upload/files/EID-SK_2016.pem.crt \
 https://sk.ee/upload/files/KLASS3-SK_2010_EECCRCA.pem.crt \
 https://www.sk.ee/upload/files/KLASS3-SK_2016_EECCRCA_SHA384.pem.crt \
 > ./etc.nginx/esteid_certs/id.crt
```

## Run the project with ID Card authentication

* Insert your card into the card reader :)

* Build and start docker containers by running `docker-compose up` in the current directory.

* Visit https://127.0.0.1.xip.io:8443/new-auth/ in the browser. Add a security exception for the host,
  because it uses a self-signed certificate.

* Open the link https://auth.127.0.0.1.xip.io:8443 in the browser and add a security exception there, too.
  If you are asked for the ID card PIN code, it's safe to just press Cancel now. If you do enter the code, 
  you will not be asked for it by the browser for some time (on the order of 5 min) - browser caches it.

* Click on ID-Card icon, you will be asked for the PIN code, if you haven't yet entered it on the previous step
  or its cache (in browser) has expired. Then you should see the same dialog as with SmartID/MobileID authentication.

## Known issues of the test server 

* There is no specific location section. In real apps, probably only the location of the authentication view
  should be passing requests to the upstream;
* There is no handling of errors that do not send a `postMessage` from the iframe. 
