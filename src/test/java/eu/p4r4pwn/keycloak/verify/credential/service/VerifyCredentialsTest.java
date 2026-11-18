package eu.p4r4pwn.keycloak.verify.credential.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import eu.p4r4pwn.keycloak.verify.credential.service.resource.dto.VerifyCredential;
import eu.p4r4pwn.keycloak.verify.credential.service.utils.JWEUtils;
import org.junit.jupiter.api.BeforeAll;
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
            .withRealmImportFiles("/realms/plain.json", "/realms/jwe.json")
            .withDefaultProviderClasses();

    static String plainStorageRealm;
    static String jweStorageRealm;

    @BeforeAll
    static void setupTests() {
        plainStorageRealm = keycloak.getAuthServerUrl() + "/realms/plain";
        jweStorageRealm = keycloak.getAuthServerUrl() + "/realms/jwe";
    }

    @Test
    void createAndUpdate_plainCredential_shouldSucceed() throws IOException, InterruptedException {
        final HttpClient client = HttpClient.newHttpClient();
        addAuthorizationHeaders(client);
        ObjectMapper mapper = new ObjectMapper();
        VerifyCredential credentialRepr = new VerifyCredential("testuser", "hello-password");

        // build the request
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(plainStorageRealm + "/verify-creds/users/testuser/resources/world"))
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
                .uri(URI.create(plainStorageRealm + "/verify-creds/users/testuser/resources/world"))
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
                .uri(URI.create(plainStorageRealm + "/verify-creds/users/testuser/resources/noworld"))
                .header("Content-Type", "application/json")
                .GET()
                .build();

        // send the request
        HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        // this should not exist
        assertEquals(404, httpResponse.statusCode());
    }

    @Test
    void createThenRetrieve_plainCredential_shouldSucceed() throws IOException, InterruptedException {
        final HttpClient client = HttpClient.newHttpClient();
        addAuthorizationHeaders(client);
        ObjectMapper mapper = new ObjectMapper();
        VerifyCredential credentialRepr = new VerifyCredential("testuser", "test-password");

        // build the request
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(plainStorageRealm + "/verify-creds/users/testuser/resources/getresource"))
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
                .uri(URI.create(plainStorageRealm + "/verify-creds/users/testuser/resources/getresource"))
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

    @Test
    void createThenRetrieve_jweCredential_withReencryption_shouldSucceed() throws IOException, InterruptedException {
        final HttpClient client = HttpClient.newHttpClient();
        addAuthorizationHeaders(client);
        ObjectMapper mapper = new ObjectMapper();
        final String plaintextPassword = "password";
        final String jwe = JWEUtils.encryptContent(plaintextPassword);
        VerifyCredential credentialRepr = new VerifyCredential("testuser", "{jwe}" + jwe);

        // build the request
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(plainStorageRealm + "/verify-creds/users/testuser/resources/jweresource"))
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
                .uri(URI.create(plainStorageRealm + "/verify-creds/users/testuser/resources/jweresource"))
                .header("Content-Type", "application/json")
                .GET()
                .build();

        // send the request
        httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        VerifyCredential returnedCredential = mapper.readValue(httpResponse.body(), VerifyCredential.class);

        assertEquals(plaintextPassword, returnedCredential.getPassword());
    }

    @Test
    void createThenUpdate_jweCredential_noReencryption_shouldSucceed() throws IOException, InterruptedException {
        final HttpClient client = HttpClient.newHttpClient();
        addAuthorizationHeaders(client);
        ObjectMapper mapper = new ObjectMapper();
        String plaintextPassword = "password";
        String jwe = JWEUtils.encryptContent(plaintextPassword);
        VerifyCredential credentialRepr = new VerifyCredential("testuser", "{jwe}" + jwe);

        // build the request
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(jweStorageRealm + "/verify-creds/users/testuser/resources/jweresource"))
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
        plaintextPassword = "password2";
        jwe = JWEUtils.encryptContent(plaintextPassword);
        credentialRepr = new VerifyCredential("testuser", "{jwe}" + jwe);

        // build the request
        httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(jweStorageRealm + "/verify-creds/users/testuser/resources/jweresource"))
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

    void addAuthorizationHeaders(final HttpClient client) {
        // no authorization yet ...
    }
}
