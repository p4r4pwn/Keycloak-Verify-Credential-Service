package eu.p4r4pwn.keycloak.verify.credential.service.services;

import eu.p4r4pwn.keycloak.verify.credential.service.credential.VerifyEncryptedCredentialProviderFactory;
import eu.p4r4pwn.keycloak.verify.credential.service.model.credential.VerifyEncryptedCredentialModel;
import eu.p4r4pwn.keycloak.verify.credential.service.policy.VerifyEncryptionKeyPasswordPolicyProvider;
import eu.p4r4pwn.keycloak.verify.credential.service.policy.VerifyJWEKeyPasswordPolicyProvider;
import eu.p4r4pwn.keycloak.verify.credential.service.resource.dto.VerifyCredential;
import eu.p4r4pwn.keycloak.verify.credential.service.utils.AESUtils;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.keys.DefaultKeyManager;
import org.keycloak.keys.GeneratedAesKeyProvider;
import org.keycloak.keys.ImportedRsaKeyProvider;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Objects;
import java.util.Optional;

public class VerifyCredentialService {

    private static final Logger LOGGER = Logger.getLogger(VerifyCredentialService.class);

    protected KeycloakSession session;
    protected RealmModel realm;
    protected DefaultKeyManager keyManager;

    public VerifyCredentialService(KeycloakSession session) {
        this.session = session;
        this.realm = this.session.getContext().getRealm();
        this.keyManager = new DefaultKeyManager(session);
    }

    public VerifyCredential getResourceCredential(final UserModel user, final String resource) {
        // get the current encryption key
        final String encryptionKeyProviderName = getRealmEncryptionKeyProviderName();
        if (encryptionKeyProviderName == null || encryptionKeyProviderName.isBlank()) throw new InternalServerErrorException("no resource credential encryption key defined");
        final GeneratedAesKeyProvider encryptionKey = getEncryptionKeyProvider(encryptionKeyProviderName);
        // todo: get the encryption associated with the CredentialModel instead of the Realm, reencrypt if needed

        // Attempt to get the stored resource credential
        VerifyEncryptedCredentialModel verifyEncryptedCredentialModel =
                getVerifyEncryptedCredentialModel(user, resource, false);

        // decrypt the associated password
        final String decryptedPassword = getDecryptedPasswordValue(
                verifyEncryptedCredentialModel.getResourcePassword(), encryptionKey);


        return new VerifyCredential(
                verifyEncryptedCredentialModel.getResourceUsername(),
                decryptedPassword);
    }

    public void storeResourceCredential(final UserModel user,
                                        final String resource,
                                        final String resourceUsername,
                                        final String resourcePassword) {
        // get the current encryption key
        final String encryptionKeyProviderName = getRealmEncryptionKeyProviderName();
        if (encryptionKeyProviderName == null || encryptionKeyProviderName.isBlank()) throw new InternalServerErrorException("no resource credential encryption key defined");
        final GeneratedAesKeyProvider encryptionKey = getEncryptionKeyProvider(encryptionKeyProviderName);
        final String normalizedResourcePassword = normalizeResourcePassword(resourcePassword);
        // attempt to get existing credential
        final VerifyEncryptedCredentialModel existingModel = getVerifyEncryptedCredentialModel(user, resource, true);
        if (existingModel != null) {
            if (policyComplies(existingModel)) return; // nothing to do
            // do we verify credential here as well?
            // delete credential and continue with usual storage
            user.credentialManager().removeStoredCredentialById(existingModel.getId());
        }

        final String encryptedPassword = getEncryptedPasswordValue(normalizedResourcePassword, encryptionKey);

        // verify whether a credential already exists
        CredentialModel credentialModel = user.credentialManager().createStoredCredential(
                VerifyEncryptedCredentialModel.createFromValues(resource, resourceUsername, encryptedPassword, encryptionKeyProviderName));

        if (credentialModel == null) {
            throw new InternalServerErrorException("resource credentials could not be stored");
        }
    }

    private String normalizeResourcePassword(String resourcePassword) {
        if (!resourcePassword.startsWith("{jwe}")) return resourcePassword; // plaintext input
        LOGGER.trace("resourcePassword is a JWE");
        JWE jwe = new JWE(resourcePassword.substring("{jwe}".length()));
        final String jweKeyProviderName = getRealmJWEKeyProviderName();
        if (jweKeyProviderName == null || jweKeyProviderName.isBlank())
            throw new InternalServerErrorException("no jwe key provider name configured");
        final ImportedRsaKeyProvider encryptionKey = getJWEKeyProvider(jweKeyProviderName);

        final Key decryptionKey = encryptionKey.getKeysStream()
                .map(KeyWrapper::getPrivateKey)
                .filter(Objects::nonNull)
                .findFirst()
                .orElseThrow(() -> new InternalServerErrorException("no associated private key found"));

        try {
            jwe.getKeyStorage().setDecryptionKey(decryptionKey);
            JWE decryptedJWE = jwe.verifyAndDecodeJwe();
            LOGGER.trace("successfully decrypted jwe");
            return new String(decryptedJWE.getContent(), StandardCharsets.UTF_8);
        } catch (JWEException jweException) {
            throw new InternalServerErrorException("failed to decrypt incoming password jwe");
        }
    }

    private String getDecryptedPasswordValue(final String encryptedPassword, final GeneratedAesKeyProvider encryptionKeyProvider) {
        final KeyWrapper keyWrapper = getKeyWrapper(encryptionKeyProvider);
        return AESUtils.decryptPassword(keyWrapper, encryptedPassword);
    }

    private String getEncryptedPasswordValue(final String resourcePassword, final GeneratedAesKeyProvider encryptionKeyProvider) {
        final KeyWrapper keyWrapper = getKeyWrapper(encryptionKeyProvider);
        return AESUtils.encryptPassword(keyWrapper, resourcePassword);
    }

    private KeyWrapper getKeyWrapper(final GeneratedAesKeyProvider keyProvider) {
        return keyProvider.getKeysStream().findFirst().orElseThrow(() -> new InternalServerErrorException("no active encryption key"));
    }

    private GeneratedAesKeyProvider getEncryptionKeyProvider(final String encryptionKeyName) {
        ComponentModel componentModel = this.realm.getComponentsStream(realm.getId(), KeyProvider.class.getName())
                .filter(component -> (Objects.equals(component.getProviderId(), "aes-generated")
                        && component.getName().equals(encryptionKeyName)))
                .findFirst().orElseThrow(() -> new InternalServerErrorException("no active encryption key"));
        return new GeneratedAesKeyProvider(componentModel);
    }

    private ImportedRsaKeyProvider getJWEKeyProvider(final String keyProviderName) {
        ComponentModel componentModel = this.realm.getComponentsStream(realm.getId(), KeyProvider.class.getName())
                .filter(component -> (component.getName().equals(keyProviderName)))
                .findFirst().orElseThrow(() -> new InternalServerErrorException("no active encryption key"));
        return new ImportedRsaKeyProvider(this.realm, componentModel);
    }

    private boolean policyComplies(VerifyEncryptedCredentialModel credentialModel) {
        PasswordPolicyProvider encryptionKeyProvider = getEncryptionKeyPolicyProvider()
                .orElseThrow(() -> new InternalServerErrorException("no encryption key policy provider"));
        final String credentialEncKeyName = credentialModel.getEncryptionKeyName();
        final String realmEncKeyName = getRealmEncryptionKeyProviderName();

        Optional<PolicyError> policyError = Optional.ofNullable(encryptionKeyProvider.validate(credentialEncKeyName, realmEncKeyName));
        return policyError.isEmpty();
    }

    private String getRealmEncryptionKeyProviderName() {
        return getDefaultValue(VerifyEncryptionKeyPasswordPolicyProvider.PROVIDER_ID, "");
    }

    private String getRealmJWEKeyProviderName() {
        return getDefaultValue(VerifyJWEKeyPasswordPolicyProvider.PROVIDER_ID, "");
    }

    private <T> T getDefaultValue(String providerId, T defaultValue) {
        T ret;
        try {
            ret = this.session.getContext().getRealm().getPasswordPolicy().getPolicyConfig(providerId);
        } catch (Exception e) {
            ret = defaultValue;
        }
        if (ret == null) ret = defaultValue;
        return ret;
    }

    /**
     * Attempts to fetch the {@link VerifyEncryptionKeyPasswordPolicyProvider} config
     * @return PasswordPolicyProvider that should be the config of {@link VerifyEncryptionKeyPasswordPolicyProvider}
     */
    private Optional<PasswordPolicyProvider> getEncryptionKeyPolicyProvider() {
        PasswordPolicy policy = this.realm.getPasswordPolicy();
        for (String id : policy.getPolicies()) {
            if (id.equalsIgnoreCase(VerifyEncryptionKeyPasswordPolicyProvider.PROVIDER_ID)) {
                return Optional.of(session.getProvider(PasswordPolicyProvider.class, id));
            }
        }
        return Optional.empty();
    }

    private VerifyEncryptedCredentialModel getVerifyEncryptedCredentialModel(final UserModel user,
                                                                             final String resource,
                                                                             final boolean nullable) {
        CredentialModel credentialModel = user.credentialManager().getStoredCredentialByNameAndType(
                resource, VerifyEncryptedCredentialProviderFactory.PROVIDER_ID);

        if (credentialModel == null) {
            if (nullable) return null;
            throw new NotFoundException("resource credential not found");
        }
        return VerifyEncryptedCredentialModel.createFromCredentialModel(credentialModel);
    }
}
