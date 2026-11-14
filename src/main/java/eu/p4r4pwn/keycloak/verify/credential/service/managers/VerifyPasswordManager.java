package eu.p4r4pwn.keycloak.verify.credential.service.managers;

import eu.p4r4pwn.keycloak.verify.credential.service.credential.VerifyEncryptedCredentialProviderFactory;
import eu.p4r4pwn.keycloak.verify.credential.service.enums.StorageFormat;
import eu.p4r4pwn.keycloak.verify.credential.service.enums.UpdateCredentialResult;
import eu.p4r4pwn.keycloak.verify.credential.service.model.credential.VerifyEncryptedCredentialModel;
import eu.p4r4pwn.keycloak.verify.credential.service.policy.VerifyEncryptionKeyPasswordPolicyProvider;
import eu.p4r4pwn.keycloak.verify.credential.service.policy.VerifyJWEKeyPasswordPolicyProvider;
import eu.p4r4pwn.keycloak.verify.credential.service.policy.VerifyPasswordStorageFormatPolicyProvider;
import eu.p4r4pwn.keycloak.verify.credential.service.resource.dto.VerifyCredential;
import eu.p4r4pwn.keycloak.verify.credential.service.utils.AESUtils;
import jakarta.ws.rs.InternalServerErrorException;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.keys.GeneratedAesKeyProvider;
import org.keycloak.keys.ImportedRsaKeyProvider;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Objects;
import java.util.Optional;

public class VerifyPasswordManager {

    private static final Logger LOGGER = Logger.getLogger(VerifyPasswordManager.class);

    protected KeycloakSession session;
    protected RealmModel realm;
    protected String realmEncryptionKeyName;
    protected GeneratedAesKeyProvider realmEncryptionKey;

    public VerifyPasswordManager(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
    }

    public Optional<VerifyEncryptedCredentialModel> getResourceCredentialForUser(final UserModel user,
                                                                                 final String resource) {
        CredentialModel credentialModel = user.credentialManager().getStoredCredentialByNameAndType(
                resource, VerifyEncryptedCredentialProviderFactory.PROVIDER_ID);

        return Optional.ofNullable(VerifyEncryptedCredentialModel.createFromCredentialModel(credentialModel));
    }

    public VerifyCredential getVerifyCredentialRepr(final VerifyEncryptedCredentialModel credentialModel) {
        loadOrGetRealmEncryptionKey();

        final String encryptedResourcePassword = credentialModel.getResourcePassword();

        if (!isUsingCurrentEncryptionKey(credentialModel)) {
            // todo requires reeencryption
            LOGGER.trace("password requires reencryption");
        }

        // decrypt the password with the associated encryption key, assume it is the realm encryption key
        // because we would have reencrypted it prior
        final String decryptedPassword = getDecryptedPasswordValue(encryptedResourcePassword);

        return new VerifyCredential(
                credentialModel.getResourceUsername(),
                decryptedPassword);
    }

    public UpdateCredentialResult storeResourceCredentialForUser(final UserModel user, final String resource,
                                                  final String resourceUsername,
                                                  final String resourcePassword) {
        UpdateCredentialResult updateCredentialResult;
        // Get the current encryption key
        final String encryptionKeyProviderName = getRealmEncryptionKeyProviderName();
        if (encryptionKeyProviderName == null || encryptionKeyProviderName.isBlank())
            throw new InternalServerErrorException("no resource credential encryption key defined");
        final GeneratedAesKeyProvider encryptionKey = getEncryptionKeyProvider(encryptionKeyProviderName);

        // Check if there is an existing credential
        final Optional<VerifyEncryptedCredentialModel> existingModel = getResourceCredentialForUser(user, resource);

        // Assume the new credential is different, so we simply remove the old one
        if (existingModel.isPresent()) {
            updateCredentialResult = UpdateCredentialResult.UPDATED;
            user.credentialManager().removeStoredCredentialById(existingModel.get().getId());
        } else {
            updateCredentialResult = UpdateCredentialResult.CREATED;
        }

        // Get the expected storage format
        final StorageFormat realmStorageFormat = getRealmStorageFormat();

        final Optional<PasswordStorageRecord> storageRecord =
                getResourcePasswordForStorage(realmStorageFormat, resourcePassword, encryptionKey);

        if (storageRecord.isEmpty()) throw new InternalServerErrorException("failed to prepare password for stoage");

        // Store the credential
        CredentialModel credentialModel = user.credentialManager().createStoredCredential(
                VerifyEncryptedCredentialModel
                        .createFromValues(resource, resourceUsername,
                                storageRecord.get().password,
                                encryptionKeyProviderName,
                                storageRecord.get().storageFormat.getStorageFormat())
        );

        if (credentialModel == null) {
            updateCredentialResult = UpdateCredentialResult.FAILED;
        }

        return updateCredentialResult;
    }

    protected Optional<PasswordStorageRecord> getResourcePasswordForStorage(final StorageFormat storageFormat,
                                                                            final String resourcePassword,
                                                                            final GeneratedAesKeyProvider encryptionKey) {
        // when realm format is jwe, and it is jwe, no action is needed
        if (storageFormat == StorageFormat.JWE && isInputPasswordJWE(resourcePassword))
            return Optional.of(new PasswordStorageRecord(storageFormat, resourcePassword));

        // if realm format is plain, and input is jwe, decrypt jwe and reencrypt the jwe payload
        if (storageFormat == StorageFormat.PLAIN && isInputPasswordJWE(resourcePassword)) {
            final String jwePayload = normalizeResourcePassword(resourcePassword);
            return Optional.of(
                    new PasswordStorageRecord(storageFormat, getEncryptedPasswordValue(jwePayload, encryptionKey))
            );
        }

        // if realm format is plain, and input is plain, encrypt the input
        if (storageFormat == StorageFormat.PLAIN && !isInputPasswordJWE(resourcePassword))
            return Optional.of(
                    new PasswordStorageRecord(storageFormat, getEncryptedPasswordValue(resourcePassword, encryptionKey))
            );

        // if realm for is jwe, and input is not jwe, we cannot do anything
        if (storageFormat == StorageFormat.JWE && !isInputPasswordJWE(resourcePassword))
            throw new InternalServerErrorException("expected storage format is jwe, but received plaintext");

        // other cases return empty
        return Optional.empty();
    }

    protected boolean isInputPasswordJWE(final String resourcePassword) {
        return resourcePassword.startsWith("{jwe}");
    }

    protected String getEncryptedPasswordValue(final String resourcePassword, final GeneratedAesKeyProvider encryptionKeyProvider) {
        final KeyWrapper keyWrapper = getKeyWrapper(encryptionKeyProvider);
        return AESUtils.encryptPassword(keyWrapper, resourcePassword);
    }

    protected String normalizeResourcePassword(final String resourcePassword) {
        LOGGER.trace("resourcePassword is a JWE");
        final JWE jwe = new JWE(resourcePassword.substring("{jwe}".length()));
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
            final JWE decryptedJWE = jwe.verifyAndDecodeJwe();
            LOGGER.trace("successfully decrypted jwe");
            return new String(decryptedJWE.getContent(), StandardCharsets.UTF_8);
        } catch (JWEException jweException) {
            throw new InternalServerErrorException("failed to decrypt incoming password jwe");
        }
    }

    protected ImportedRsaKeyProvider getJWEKeyProvider(final String keyProviderName) {
        ComponentModel componentModel = this.realm.getComponentsStream(realm.getId(), KeyProvider.class.getName())
                .filter(component -> (component.getName().equals(keyProviderName)))
                .findFirst().orElseThrow(() -> new InternalServerErrorException("no active encryption key"));
        return new ImportedRsaKeyProvider(this.realm, componentModel);
    }

    protected StorageFormat getRealmStorageFormat() {
        final String storageFormat = getDefaultValue(VerifyPasswordStorageFormatPolicyProvider.PROVIDER_ID, "");
        return StorageFormat.parseStorageFormat(storageFormat);
    }

    protected String getRealmJWEKeyProviderName() {
        return getDefaultValue(VerifyJWEKeyPasswordPolicyProvider.PROVIDER_ID, "");
    }

    protected boolean isUsingCurrentEncryptionKey(final VerifyEncryptedCredentialModel credentialModel) {
        return this.realmEncryptionKeyName.equalsIgnoreCase(credentialModel.getEncryptionKeyName());
    }

    private String getDecryptedPasswordValue(final String encryptedPassword) {
        final KeyWrapper keyWrapper = getKeyWrapper(this.realmEncryptionKey);
        return AESUtils.decryptPassword(keyWrapper, encryptedPassword);
    }

    protected KeyWrapper getKeyWrapper(final GeneratedAesKeyProvider keyProvider) {
        return keyProvider.getKeysStream().findFirst().orElseThrow(() -> new InternalServerErrorException("no active encryption key"));
    }

    protected void loadOrGetRealmEncryptionKey() {
        if (realmEncryptionKey != null) return;
        this.realmEncryptionKeyName = getRealmEncryptionKeyProviderName();
        if (this.realmEncryptionKeyName == null || this.realmEncryptionKeyName.isBlank())
            throw new InternalServerErrorException("no resource credential encryption key defined");
        this.realmEncryptionKey = getEncryptionKeyProvider(this.realmEncryptionKeyName);
    }

    protected GeneratedAesKeyProvider getEncryptionKeyProvider(final String encryptionKeyName) {
        ComponentModel componentModel = this.realm.getComponentsStream(realm.getId(), KeyProvider.class.getName())
                .filter(component -> (Objects.equals(component.getProviderId(), "aes-generated")
                        && component.getName().equals(encryptionKeyName)))
                .findFirst().orElseThrow(() -> new InternalServerErrorException("no active encryption key"));
        return new GeneratedAesKeyProvider(componentModel);
    }

    protected String getRealmEncryptionKeyProviderName() {
        return getDefaultValue(VerifyEncryptionKeyPasswordPolicyProvider.PROVIDER_ID, "");
    }

    protected <T> T getDefaultValue(String providerId, T defaultValue) {
        T ret;
        try {
            ret = this.session.getContext().getRealm().getPasswordPolicy().getPolicyConfig(providerId);
        } catch (Exception e) {
            ret = defaultValue;
        }
        if (ret == null) ret = defaultValue;
        return ret;
    }

    protected record PasswordStorageRecord(StorageFormat storageFormat, String password) {}
}
