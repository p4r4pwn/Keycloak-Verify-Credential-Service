package eu.p4r4pwn.keycloak.verify.credential.service.policy;

import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;
import org.keycloak.policy.PolicyError;

public class VerifyEncryptionKeyPasswordPolicyProvider implements PasswordPolicyProvider, PasswordPolicyProviderFactory {
    public static final String PROVIDER_ID = "verify-cred-enc-key";

    private static final String ENC_KEY_PROVIDER_MISMATCH = "encryptionKeyProviderMismatch";
    private KeycloakContext context;

    public VerifyEncryptionKeyPasswordPolicyProvider() {}

    public VerifyEncryptionKeyPasswordPolicyProvider(KeycloakContext context) {
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
        // user == credential key provider, password == realm key provider policy
        return !user.equalsIgnoreCase(password) ? new PolicyError(ENC_KEY_PROVIDER_MISMATCH) : null;
    }

    @Override
    public Object parseConfig(String value) {
        return value;
    }

    @Override
    public String getDisplayName() {
        return "Credential Service Enc Key ID";
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
