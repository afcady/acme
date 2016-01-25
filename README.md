# Let's Encrypt ACME protocol

```
Let's Encrypt! ACME client

Usage: acme-certify --key FILE --domain DOMAIN --challenge-dir DIR
                    [--domain-dir DIR] [--email ADDRESS] [--terms URL]
                    [--staging]
  This program will generate a signed TLS certificate using the ACME protocol
  and the free Let's Encrypt! CA.

Available options:
  -h,--help                Show this help text
  --key FILE               filename of your private RSA key
  --domain DOMAIN          the domain name(s) to certify; specify more than once
                           for a multi-domain certificate
  --challenge-dir DIR      output directory for ACME challenges
  --domain-dir DIR         directory in which to domain certificates and keys
                           are stored; the default is to use the (first) domain
                           name as a directory name
  --email ADDRESS          an email address with which to register an account
  --terms URL              the terms param of the registration request
  --staging                use staging servers instead of live servers
                           (generated certificates will not be trusted!)
```

This program can be used to obtain a certificate from
[Let's Encrypt](https://letsencrypt.org/) using their ACME protocol.

## Rate Limits

This tool supports multiple domain names per certificate. Note that `Let's
Encrypt` will not sign a certificate with more than 100 names; nor will it allow
more than 100 names to be signed for a single domain (no matter how many
certificates the names are spread across). Furthermore, you can only issue 5
certificates per domain per week.

The `Let's Encrypt` community documentation contains more
[information about rate limits](https://community.letsencrypt.org/t/rate-limits-for-lets-encrypt/6769).

## User account keys

Under ACME, each certificate request is associated with a private key used to
sign communications with the ACME server. The key is furthermore associated with
an email address.

Note: `Let's Encrypt` requires that this key be different from the key used for
the certificate.

Use the `--email` command line argument to specify an email address to associate
with a private key.  If there is no private key, one will be generated;
otherwise, the existing one will be used.  This only needs to be done once per
private key.

Currently, only RSA keys are supported by this tool.  You can generate compatible
keys like this:

```
openssl genrsa 4096 > user.key
mkdir -p ${DOMAIN}
openssl genrsa 4096 > ${DOMAIN}/rsa.key
```

## Receive certificate

The signed certificate will be saved by this program in
``./${DOMAIN}/cert.der``. You can copy that file to the place your TLS
server is configured to read it.

You can also view the certificate like so:

```
openssl x509 -inform der -in ${DOMAIN}/cert.der  -noout -text | less
```

## Create a certificate for HAProxy

Vo Minh Thu, the original author of this program, suggests to include explicit
DH key exchange parameters to prevent the [Logjam attack](https://weakdh.org/).

```
> openssl x509 -inform der -in ${DOMAIN}/cert.der \
    -out ${DOMAIN}/cert.pem
> openssl dhparam -out ${DOMAIN}/dhparams.pem 2048
> cat ${DOMAIN}/cert.pem \
    lets-encrypt-x1-cross-signed.pem \
    ${DOMAIN}/rsa.key \
    ${DOMAIN}/dhparams.pem > aaa.reesd.com-combined.pem
```
