package eu.p4r4pwn.keycloak.verify.credential.service.resource;

import eu.p4r4pwn.keycloak.verify.credential.service.resource.dto.VerifyCredential;
import eu.p4r4pwn.keycloak.verify.credential.service.services.VerifyCredentialService;
import io.smallrye.common.constraint.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

public class VerifyCredentialUserResources {
    private final UserModel user;

    private final VerifyCredentialService credentialsService;

    public VerifyCredentialUserResources(KeycloakSession session, UserModel user) {
        this.user = user;
        this.credentialsService = new VerifyCredentialService(session);
    }

    @Path("/resources/{resource}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getResource(@NotNull String resource) {
        VerifyCredential verifyCredential = this.credentialsService.getResourceCredential(this.user, resource);
        return Response.ok(verifyCredential).build();
    }

    @Path("/resources/{resource}")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public Response getResource(@NotNull String resource, VerifyCredential verifyCredential) {
        this.credentialsService.storeResourceCredential(this.user, resource, verifyCredential.getUsername(), verifyCredential.getPassword());
        return Response.status(201).build();
    }
}
