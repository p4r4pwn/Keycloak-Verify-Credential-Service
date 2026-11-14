# Notes

## RSA vs ECDSA

I was first experimenting with ECDSA keys, but due to a combination of limitations:
+ IAG needs a private key + certificate
+ Keycloak does not make the private key exportable for ECDH

I had to switch to RSA, because:
+ Keycloak allows creating an RSA-based JWK using the `rsa-enc` provider
+ IAG requirement is also satisfied

## JWE as storage

The whole RSA vs ECDSA discussion matters because I don't want to store an entire JWE as credential, but I am more interested in the actual password.

So, by having the RSA keypair in Keycloak, I can decrypt the JWE, extract the password string, and store it using AES256GCM using a key of my choosing.

Afterward, the password is returned to IAG without `{jwe}` prefix, and is interpreted as-is.

This will eventually allow for ciphertext rotation based on changing policies.

## IBM Application Gateway

### segfaults

IAG needs a private key + certificate combination supplied as `enc_key: '@vault-key.pem'`:

```pem
-----BEGIN PRIVATE KEY-----
RSA key ...
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
x509v3 cert
-----END CERTIFICATE-----
```

Which can be generated using:

```sh
openssl genrsa -out vault-private-key.pem 2048;
openssl req -new -x509\
  -key vault-private-key.pem\
  -out vault-cert.pem\
  -days 3650\
  -subj "/CN=iag-vault-cred-key";
cat vault-private-key.pem vault-cert.pem > vault-key.pem
```

If you only supply a private key or only a certificate, the container immediately crashes using rc 139 (SIGSEGV), which had me baffled for some time 🙃.