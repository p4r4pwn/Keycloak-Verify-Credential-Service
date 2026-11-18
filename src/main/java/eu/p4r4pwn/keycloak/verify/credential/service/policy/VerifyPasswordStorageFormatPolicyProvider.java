package eu.p4r4pwn.keycloak.verify.credential.service.policy;

import eu.p4r4pwn.keycloak.verify.credential.service.enums.StorageFormat;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.policy.PasswordPolicyConfigException;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;
import org.keycloak.policy.PolicyError;

import java.util.Arrays;
import java.util.stream.Collectors;

public class VerifyPasswordStorageFormatPolicyProvider implements PasswordPolicyProvider, PasswordPolicyProviderFactory {
    public static final String PROVIDER_ID = "verify-cred-storage-format";

    private static final String ENC_KEY_PROVIDER_MISMATCH = "encryptionKeyProviderMismatch";
    private static final String DEFAULT_STORAGE_FORMAT = StorageFormat.JWE.getStorageFormat();
    private KeycloakContext context;

    public VerifyPasswordStorageFormatPolicyProvider() {}

    public VerifyPasswordStorageFormatPolicyProvider(KeycloakContext context) {
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
        final StorageFormat storageFormat = StorageFormat.parseStorageFormat(value);
        if (storageFormat == null) {
            final String allowedStorageFormats = Arrays.stream(StorageFormat.values())
                    .map(StorageFormat::getStorageFormat)
                    .collect(Collectors.joining(", "));
            throw new PasswordPolicyConfigException("Storage format should be one of: [" + allowedStorageFormats + "].");
        }
        return storageFormat.getStorageFormat();
    }

    @Override
    public String getDisplayName() {
        return "Credential Service Storage Format";
    }

    @Override
    public String getConfigType() {
        return PasswordPolicyProvider.STRING_CONFIG_TYPE;
    }

    @Override
    public String getDefaultConfigValue() {
        return DEFAULT_STORAGE_FORMAT;
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
