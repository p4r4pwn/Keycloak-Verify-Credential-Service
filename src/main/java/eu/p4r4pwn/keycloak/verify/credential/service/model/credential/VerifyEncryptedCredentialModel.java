package eu.p4r4pwn.keycloak.verify.credential.service.model.credential;

import eu.p4r4pwn.keycloak.verify.credential.service.credential.VerifyEncryptedCredentialProviderFactory;
import eu.p4r4pwn.keycloak.verify.credential.service.model.credential.dto.VerifyCredentialData;
import eu.p4r4pwn.keycloak.verify.credential.service.model.credential.dto.VerifyEncryptedCredentialSecret;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

import static org.keycloak.utils.StringUtil.isBlank;

public class VerifyEncryptedCredentialModel extends CredentialModel {

    private final VerifyCredentialData credentialData;
    private final VerifyEncryptedCredentialSecret secretData;

    public VerifyEncryptedCredentialModel(VerifyCredentialData credentialData, VerifyEncryptedCredentialSecret secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
    }

    public VerifyEncryptedCredentialModel(String resource, VerifyCredentialData credentialData, VerifyEncryptedCredentialSecret secretData) {
        this.setUserLabel(resource);
        this.credentialData = credentialData;
        this.secretData = secretData;
    }

    public static VerifyEncryptedCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        try {
            VerifyCredentialData credentialData = isBlank(credentialModel.getCredentialData()) ? null :
                    JsonSerialization.readValue(credentialModel.getCredentialData(), VerifyCredentialData.class);
            VerifyEncryptedCredentialSecret secretData = isBlank(credentialModel.getSecretData()) ? null :
                    JsonSerialization.readValue(credentialModel.getSecretData(), VerifyEncryptedCredentialSecret.class);
            VerifyEncryptedCredentialModel verifyEncryptedCredentialModel = new VerifyEncryptedCredentialModel(credentialData, secretData);

            verifyEncryptedCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
            verifyEncryptedCredentialModel.setCredentialData(credentialModel.getCredentialData());
            verifyEncryptedCredentialModel.setId(credentialModel.getId());
            verifyEncryptedCredentialModel.setSecretData(credentialModel.getSecretData());
            verifyEncryptedCredentialModel.setType(credentialModel.getType());
            verifyEncryptedCredentialModel.setUserLabel(credentialModel.getUserLabel());

            return verifyEncryptedCredentialModel;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static VerifyEncryptedCredentialModel createFromValues(final String resource,
                                                                  final String resourceUsername,
                                                                  final String resourcePassword,
                                                                  final String keyName) {
        VerifyCredentialData credentialData = new VerifyCredentialData(resourceUsername, "plain", keyName);
        VerifyEncryptedCredentialSecret secretData = new VerifyEncryptedCredentialSecret(resourcePassword);
        VerifyEncryptedCredentialModel verifyEncryptedCredentialModel = new VerifyEncryptedCredentialModel(resource, credentialData, secretData);

        try {
            verifyEncryptedCredentialModel.setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            verifyEncryptedCredentialModel.setSecretData(JsonSerialization.writeValueAsString(secretData));
            verifyEncryptedCredentialModel.setType(verifyEncryptedCredentialModel.getType());
            verifyEncryptedCredentialModel.setUserLabel(resource);
            verifyEncryptedCredentialModel.setCreatedDate(Time.currentTimeMillis());
            return verifyEncryptedCredentialModel;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String getResourcePassword() {
        return this.secretData.getValue();
    }

    public String getResourceUsername() {
        return this.credentialData.getUsername();
    }

    public String getEncryptionKeyName() {
        return this.credentialData.getKeyName();
    }

    @Override
    public String getType() {
        return VerifyEncryptedCredentialProviderFactory.PROVIDER_ID;
    }
}
