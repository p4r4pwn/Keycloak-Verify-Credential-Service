package eu.p4r4pwn.keycloak.verify.credential.service.resource;

import io.smallrye.common.constraint.NotNull;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Optional;

public class VerifyCredentialResource {

    protected KeycloakSession session;
    protected RealmModel realm;

    public VerifyCredentialResource(KeycloakSession session) {
        this.session = session;
        this.realm = this.session.getContext().getRealm();
    }

    @Path("/users/{user}")
    public VerifyCredentialUserResources getUsersResources(@NotNull String user) {
        final UserModel userModel = getUser(user).orElseThrow(() -> new NotFoundException("user not found"));
        return new VerifyCredentialUserResources(session, userModel);
    }

    private Optional<UserModel> getUser(final String username) {
        UserModel user = this.session.users().getUserByUsername(this.realm, username);
        if (user == null) user = this.session.users().getUserByEmail(this.realm, username);
        if (user == null) return Optional.empty();
        // throw error here instead
        return Optional.of(user);
    }
}
