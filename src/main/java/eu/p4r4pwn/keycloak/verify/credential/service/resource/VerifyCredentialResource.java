package eu.p4r4pwn.keycloak.verify.credential.service.resource;

import eu.p4r4pwn.keycloak.verify.credential.service.managers.UserManager;
import io.smallrye.common.constraint.NotNull;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class VerifyCredentialResource {

    protected KeycloakSession session;
    protected RealmModel realm;
    protected UserManager userManager;

    public VerifyCredentialResource(KeycloakSession session) {
        this.session = session;
        this.realm = this.session.getContext().getRealm();
        this.userManager = new UserManager(this.session);
    }

    @Path("/users/{user}")
    public VerifyCredentialUserResources getUsersResources(@NotNull String user) {
        final UserModel userModel = userManager.getUser(user).orElseThrow(() -> new NotFoundException("user not found"));
        return new VerifyCredentialUserResources(session, userModel);
    }
}
