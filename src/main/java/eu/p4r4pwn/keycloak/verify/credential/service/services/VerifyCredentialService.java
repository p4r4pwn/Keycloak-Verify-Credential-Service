package eu.p4r4pwn.keycloak.verify.credential.service.services;

import eu.p4r4pwn.keycloak.verify.credential.service.credential.VerifyEncryptedCredentialProviderFactory;
import eu.p4r4pwn.keycloak.verify.credential.service.model.credential.VerifyEncryptedCredentialModel;
import eu.p4r4pwn.keycloak.verify.credential.service.resource.dto.VerifyCredential;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class VerifyCredentialService {
    protected KeycloakSession session;
    protected RealmModel realm;

    public VerifyCredentialService(KeycloakSession session) {
        this.session = session;
        this.realm = this.session.getContext().getRealm();
    }

    public VerifyCredential getUserCredential(final UserModel user, final String resource) {
        VerifyEncryptedCredentialModel verifyEncryptedCredentialModel = getVerifyEncryptedCredentialModel(user, resource);

        return new VerifyCredential(
                verifyEncryptedCredentialModel.getResourceUsername(),
                verifyEncryptedCredentialModel.getResourcePassword());
    }

    public void storeResourceCredential(final UserModel user,
                                        final String resource,
                                        final String resourceUsername,
                                        final String resourcePassword) {
        // todo do we perform encryption here?
        // verify whether a credential already exists
        CredentialModel credentialModel = user.credentialManager().createStoredCredential(
                VerifyEncryptedCredentialModel.createFromValues(resource, resourceUsername, resourcePassword));

        if (credentialModel == null) {
            throw new InternalServerErrorException("resource credentials could not be stored");
        }
    }

    private VerifyEncryptedCredentialModel getVerifyEncryptedCredentialModel(final UserModel user, final String resource) {
        CredentialModel credentialModel = user.credentialManager().getStoredCredentialByNameAndType(
                resource, VerifyEncryptedCredentialProviderFactory.PROVIDER_ID);

        if (credentialModel == null) {
            throw new NotFoundException("resource credential not found");
        }
        return VerifyEncryptedCredentialModel.createFromCredentialModel(credentialModel);
    }
}
