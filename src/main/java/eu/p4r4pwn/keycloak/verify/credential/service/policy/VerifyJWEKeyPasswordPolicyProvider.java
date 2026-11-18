package eu.p4r4pwn.keycloak.verify.credential.service.policy;

import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;
import org.keycloak.policy.PolicyError;

public class VerifyJWEKeyPasswordPolicyProvider implements PasswordPolicyProvider, PasswordPolicyProviderFactory {
    public static final String PROVIDER_ID = "verify-cred-jwe-key";
    private KeycloakContext context;

    public VerifyJWEKeyPasswordPolicyProvider() {}

    public VerifyJWEKeyPasswordPolicyProvider(KeycloakContext context) {
        this.context = context;
    }

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        return this;
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
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        return null;
    }

    @Override
    public PolicyError validate(String user, String password) {
        return null;
    }

    @Override
    public Object parseConfig(String value) {
        return value;
    }

    @Override
    public String getDisplayName() {
        return "Credential Service JWE Key Provider";
    }

    @Override
    public String getConfigType() {
        return PasswordPolicyProvider.STRING_CONFIG_TYPE;
    }

    @Override
    public String getDefaultConfigValue() {
        return "";
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }

    @Override
    public void close() {
        // noop
    }
}
