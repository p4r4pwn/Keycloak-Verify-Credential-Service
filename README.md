# Verify Credential Service

Provides a [Credential Service](https://docs.verify.ibm.com/gateway/docs/tasks-credential-service) implementation in Keycloak.

Currently supports:
+ Plaintext storage of resource passwords

Roadmap:
+ [ ] Password encryption: Use a realm AES256 key for encryption
+ [ ] Encryption policies: Config which key to use, probably use Password Policy Providers
+ [ ] Re-encryption policies: Re-encrypt according to encryption policies
+ [ ] JWE storage: Support of JWE storage
+ [ ] API Authorization: Use resource-server client with roles + client credentials for IAG
