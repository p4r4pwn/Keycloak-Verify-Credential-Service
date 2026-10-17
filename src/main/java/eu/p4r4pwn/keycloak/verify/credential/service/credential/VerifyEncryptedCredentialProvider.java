package eu.p4r4pwn.keycloak.verify.credential.service.credential;

import eu.p4r4pwn.keycloak.verify.credential.service.model.credential.VerifyEncryptedCredentialModel;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class VerifyEncryptedCredentialProvider implements CredentialProvider<VerifyEncryptedCredentialModel>,
        CredentialInputValidator {
    protected KeycloakSession session;

    public VerifyEncryptedCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, VerifyEncryptedCredentialModel credentialModel) {
        return user.credentialManager().createStoredCredential(credentialModel);
    }

    @Override
    public VerifyEncryptedCredentialModel getCredentialFromModel(CredentialModel model) {
        return VerifyEncryptedCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return true;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        return false;
    }

    @Override
    public String getType() {
        return VerifyEncryptedCredentialProviderFactory.PROVIDER_ID;
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return false;
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return null;
    }

    @Override
    public void close() {
        // noop
    }

    @Override
    public boolean supportsCredentialType(String type) {
        return CredentialProvider.super.supportsCredentialType(type);
    }
}
