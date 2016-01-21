# Let's Encrypt ACME protocol

```
Let's Encrypt! ACME client

Usage: acme-encrypt-exe --key FILE --domain DOMAIN --challenge-dir DIR
                        [--domain-dir DIR] [--email ADDRESS] [--terms URL]
                        [--staging]
  This is a work in progress.

Available options:
  -h,--help                Show this help text
  --key FILE               filename of your private RSA key
  --domain DOMAIN          the domain name to certify
  --challenge-dir DIR      output directory for ACME challenges
  --domain-dir DIR         directory in which to domain certificates and keys
                           are stored; the default is to use the domain name as
                           a directory name
  --email ADDRESS          an email address with which to register an account
  --terms URL              the terms param of the registration request
  --staging                use staging servers instead of live servers
                           (certificates will not be real!)
```

This is a simple Haskell script to obtain a certificate from [Let's
Encrypt](https://letsencrypt.org/) using their ACME protocol.


- The main source of information to write this was
  https://github.com/diafygi/letsencrypt-nosudo

- The ACME spec: https://letsencrypt.github.io/acme-spec/

## Generate user account keys

The needed keys will be automatically generated with HsOpenSSL. You can also
pre-generate them manually, in which case they won't be overwritten:


```
openssl genrsa 4096 > user.key
mkdir -p ${DOMAIN_NAME}
openssl genrsa 4096 > ${DOMAIN_NAME}/rsa.key
```

## Send CSR 

The CSR will be automatically created.  You can also create it yourself with:

```
> openssl req -new -sha256 -key ${DOMAIN}/rsa.key \
      -subj "/CN=aaa.reesd.com" -outform DER > ${DOMAIN}/csr.der
```

## Receive certificate

The signed certificate will be saved by this program in
``./${DOMAIN}/cert.der``. You can copy that file to the place your TLS server is
configured to read it.

You can also view the certificate like so:

```
> openssl x509 -inform der -in ${DOMAIN}/cert.der  -noout -text | less
```

## Create a certificate for HAProxy

Including explicit DH key exchange parameters to prevent Logjam attack
(https://weakdh.org/).

```
> openssl x509 -inform der -in ${DOMAIN}/cert.der \
    -out ${DOMAIN}/cert.pem
> openssl dhparam -out ${DOMAIN}/dhparams.pem 2048
> cat ${DOMAIN}/cert.pem \
    lets-encrypt-x1-cross-signed.pem \
    ${DOMAIN}/rsa.key \
    ${DOMAIN}/dhparams.pem > aaa.reesd.com-combined.pem
```
