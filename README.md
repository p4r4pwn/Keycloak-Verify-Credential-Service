# Verify Credential Service

Provides a [Credential Service](https://docs.verify.ibm.com/gateway/docs/tasks-credential-service) implementation in Keycloak.

Currently supports:
+ Plaintext storage of resource passwords
+ Password encryption: Use a realm AES256 key for encryption
+ Encryption policies: Config which key to use, probably use Password Policy Providers

Roadmap:
+ [x] Password encryption: Use a realm AES256 key for encryption
+ [x] Encryption policies: Config which key to use, probably use Password Policy Providers
+ [ ] Re-encryption policies: Re-encrypt according to encryption policies
+ [ ] JWE storage: Support of JWE storage
+ [ ] API Authorization: Use resource-server client with roles + client credentials for IAG

# Installation

Build using:

```sh
mvn clean package
```

And copy the artifact in `target/verify-credential-servic*.jar` into Keycloak's `providers/` directory.

Afterwards re-build Keycloak:

```sh
sudo -u keycloak bin/kc.sh build
```

# Usage

Supplies 2 endpoints:
+ `GET /realms/{realm}/verify-creds/users/{user}/resources/{resource}`
+ `PUT /realms/{realm}/verify-creds/users/{user}/resources/{resource}`

No API authorization yet, OAuth access tokens to come...

## Encryption Keys and Policies

You need to create:
+ `aes-generated` provider with `AES Key size = 32`
+ `rsa-enc` provider with an own-generated RSA keypair that is shared with IAG

Afterward, in `Authentication > Policies > Password policy`, create:
+ `Credential Service Enc Key ID` referencing your `aes-generated` key provider name (not kid)
+ `Credential Service JWE Key Provider` referencing the `rsa-enc` key provider name (not kid)

## Retrieving resource credentials

Just invoke a GET request to a user's resource.

## Storing resource credentials

### Plaintext

You can submit a "plaintext" password to the service, it will in turn be encrypted using the realm's AES256 key and stored as ciphertext.

### JWE

IAG and IBM's supplied demo application generate a JWE. This JWE is decrypted by the provider and the password is stored as ciphertext using the realm's AES256 key.