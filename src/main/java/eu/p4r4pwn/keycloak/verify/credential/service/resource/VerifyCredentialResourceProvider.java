package eu.p4r4pwn.keycloak.verify.credential.service.resource;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class VerifyCredentialResourceProvider implements RealmResourceProvider {
    protected KeycloakSession session;

    public VerifyCredentialResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new VerifyCredentialResource(session);
    }

    @Override
    public void close() {
        // noop
    }
}
