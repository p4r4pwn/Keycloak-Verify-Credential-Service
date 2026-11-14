package eu.p4r4pwn.keycloak.verify.credential.service.enums;

import java.util.Arrays;

public enum StorageFormat {
    PLAIN("plain"),
    JWE("jwe");

    private final String storageFormat;

    StorageFormat(String storageFormat) {
        this.storageFormat = storageFormat;
    }

    public String getStorageFormat() {
        return storageFormat;
    }

    public static boolean isValidStorageFormat(final String formatName) {
        return Arrays
                .stream(StorageFormat.values())
                .anyMatch(f -> f.storageFormat.equalsIgnoreCase(formatName));
    }

    public static StorageFormat parseStorageFormat(final String formatName) {
        if (isValidStorageFormat(formatName))
            return StorageFormat.valueOf(formatName.toUpperCase());
        return null;
    }


}
