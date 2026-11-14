package eu.p4r4pwn.keycloak.verify.credential.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import eu.p4r4pwn.keycloak.verify.credential.service.resource.dto.VerifyCredential;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Testcontainers
public class VerifyCredentialsTest {
    @Container
    static KeycloakContainer keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:26.8.1")
            .withRealmImportFile("/realms/test.json")
            .withDefaultProviderClasses();

    @Test
    void createCredential_createAndUpdate_shouldSucceed() throws IOException, InterruptedException {
        final HttpClient client = HttpClient.newHttpClient();
        addAuthorizationHeaders(client);
        ObjectMapper mapper = new ObjectMapper();
        VerifyCredential credentialRepr = new VerifyCredential("testuser", "hello-password");

        // build the request
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(keycloak.getAuthServerUrl() + "/realms/test/verify-creds/users/testuser/resources/world"))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(
                        mapper.writeValueAsString(credentialRepr)
                ))
                .build();

        // send the request
        HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        // this should have created it
        assertEquals(201, httpResponse.statusCode());

        // update the credential
        mapper = new ObjectMapper();
        credentialRepr = new VerifyCredential("testuser", "hello-password2");

        // build the request
        httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(keycloak.getAuthServerUrl() + "/realms/test/verify-creds/users/testuser/resources/world"))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(
                        mapper.writeValueAsString(credentialRepr)
                ))
                .build();

        // send the request
        httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        // this should have updated it
        assertEquals(204, httpResponse.statusCode());
    }

    @Test
    void getResourceCredential_doesntExist_shouldFail() throws IOException, InterruptedException {
        final HttpClient client = HttpClient.newHttpClient();
        addAuthorizationHeaders(client);

        // build the request
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(keycloak.getAuthServerUrl() + "/realms/test/verify-creds/users/testuser/resources/noworld"))
                .header("Content-Type", "application/json")
                .GET()
                .build();

        // send the request
        HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        // this should not exist
        assertEquals(404, httpResponse.statusCode());
    }

    @Test
    void getResourceCredential_createThenRetrieve_shouldSucceed() throws IOException, InterruptedException {
        final HttpClient client = HttpClient.newHttpClient();
        addAuthorizationHeaders(client);
        ObjectMapper mapper = new ObjectMapper();
        VerifyCredential credentialRepr = new VerifyCredential("testuser", "test-password");

        // build the request
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(keycloak.getAuthServerUrl() + "/realms/test/verify-creds/users/testuser/resources/getresource"))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(
                        mapper.writeValueAsString(credentialRepr)
                ))
                .build();

        // send the request
        HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        // this should have created it
        assertEquals(201, httpResponse.statusCode());

        // now get the resource again
        // build the request
        httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(keycloak.getAuthServerUrl() + "/realms/test/verify-creds/users/testuser/resources/getresource"))
                .header("Content-Type", "application/json")
                .GET()
                .build();

        // send the request
        httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        VerifyCredential returnedCredential = mapper.readValue(httpResponse.body(), VerifyCredential.class);

        // this should exist and return our initially submitted resource parameters
        assertEquals(200, httpResponse.statusCode());
        assertEquals(credentialRepr.getUsername(), returnedCredential.getUsername());
        assertEquals(credentialRepr.getPassword(), returnedCredential.getPassword());
    }

    void addAuthorizationHeaders(final HttpClient client) {
        // no authorization yet ...
    }
}
