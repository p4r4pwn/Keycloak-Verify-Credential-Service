package eu.p4r4pwn.keycloak.verify.credential.service.model.credential.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class VerifyEncryptedCredentialSecret {
    private final String value;

    @JsonCreator
    public VerifyEncryptedCredentialSecret(@JsonProperty("value") String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
