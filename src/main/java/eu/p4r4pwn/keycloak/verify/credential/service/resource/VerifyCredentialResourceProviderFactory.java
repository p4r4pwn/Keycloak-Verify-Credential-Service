package eu.p4r4pwn.keycloak.verify.credential.service.resource;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class VerifyCredentialResourceProviderFactory implements RealmResourceProviderFactory {
    public static final String PROVIDER_ID = "verify-creds";
    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new VerifyCredentialResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // noop
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // noop
    }

    @Override
    public void close() {
        // noop
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
