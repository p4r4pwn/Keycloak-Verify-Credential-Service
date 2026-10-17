package eu.p4r4pwn.keycloak.verify.credential.service.model.credential.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class VerifyCredentialData {
    private final String username;
    private final String format;
    private final String keyName;

    @JsonCreator
    public VerifyCredentialData(@JsonProperty("username") String username,
                                @JsonProperty("format") String format,
                                @JsonProperty("keyName") String keyName) {
        this.username = username;
        this.format = format;
        this.keyName = keyName;
    }

    public String getUsername() {
        return username;
    }

    public String getFormat() {
        return format;
    }

    public String getKeyName() {
        return keyName;
    }
}
