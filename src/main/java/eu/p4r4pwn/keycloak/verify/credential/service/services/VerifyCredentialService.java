package eu.p4r4pwn.keycloak.verify.credential.service.services;

import eu.p4r4pwn.keycloak.verify.credential.service.enums.UpdateCredentialResult;
import eu.p4r4pwn.keycloak.verify.credential.service.managers.VerifyPasswordManager;
import eu.p4r4pwn.keycloak.verify.credential.service.model.credential.VerifyEncryptedCredentialModel;
import eu.p4r4pwn.keycloak.verify.credential.service.resource.dto.VerifyCredential;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;
import org.keycloak.keys.DefaultKeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Optional;

public class VerifyCredentialService {

    protected KeycloakSession session;
    protected RealmModel realm;
    protected DefaultKeyManager keyManager;
    protected VerifyPasswordManager verifyPasswordManager;

    public VerifyCredentialService(KeycloakSession session) {
        this.session = session;
        this.realm = this.session.getContext().getRealm();
        this.keyManager = new DefaultKeyManager(session);
        this.verifyPasswordManager = new VerifyPasswordManager(this.session);
    }

    public VerifyCredential getResourceCredential(final UserModel user, final String resource) {
        // Attempt to get the stored resource credential
        final Optional<VerifyEncryptedCredentialModel> verifyEncryptedCredentialModel =
                verifyPasswordManager.getResourceCredentialForUser(user, resource);

        // throw 404 when resource credential is not found
        if (verifyEncryptedCredentialModel.isEmpty()) {
            throw new NotFoundException("resource credential not found");
        }

        return verifyPasswordManager.getVerifyCredentialRepr(verifyEncryptedCredentialModel.get());
    }

    public UpdateCredentialResult storeResourceCredential(final UserModel user,
                                        final String resource,
                                        final String resourceUsername,
                                        final String resourcePassword) {
        final UpdateCredentialResult updateCredentialResult = verifyPasswordManager
                .storeResourceCredentialForUser(user, resource, resourceUsername, resourcePassword);

        if (updateCredentialResult == UpdateCredentialResult.FAILED)
            throw new InternalServerErrorException("something went wrong storing the credential");

        return updateCredentialResult;
    }
}
