package eu.p4r4pwn.keycloak.verify.credential.service.managers;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Optional;

public class UserManager {

    protected KeycloakSession session;
    protected RealmModel realm;

    public UserManager(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
    }

    public Optional<UserModel> getUser(final String username) {
        UserModel user = this.session.users().getUserByUsername(this.realm, username);
        if (user == null) user = this.session.users().getUserByEmail(this.realm, username);
        return Optional.ofNullable(user);
    }
}
