package eu.p4r4pwn.keycloak.verify.credential.service.credential;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class VerifyEncryptedCredentialProviderFactory implements CredentialProviderFactory<VerifyEncryptedCredentialProvider> {
    public static final String PROVIDER_ID = "verify-cred";
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public VerifyEncryptedCredentialProvider create(KeycloakSession session) {
        return new VerifyEncryptedCredentialProvider(session);
    }
}
