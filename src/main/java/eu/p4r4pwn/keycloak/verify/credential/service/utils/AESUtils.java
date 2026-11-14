package eu.p4r4pwn.keycloak.verify.credential.service.utils;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwe.JWEUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Base64;

public class AESUtils {

    private static final int IV_SIZE_BYTE = 12;
    private static final int AUTH_TAG_SIZE_BITS = 128;

    private AESUtils() {
    }

    public static String decryptPassword(final KeyWrapper encryptionKey, final String b64EncryptedPassword) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(b64EncryptedPassword);
            byte[] decryptedBytes = decryptBytes(decodedBytes, encryptionKey.getSecretKey());
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    public static String encryptPassword(final KeyWrapper encryptionKey, final String password) {
        byte[] iv = JWEUtils.generateSecret(IV_SIZE_BYTE);

        try {
            byte[] encryptedBytes = encryptBytes(password.getBytes(StandardCharsets.UTF_8), iv, encryptionKey.getSecretKey());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (GeneralSecurityException e) {
            // noop
        }
        return null;
    }

    private static byte[] encryptBytes(byte[] contentBytes, byte[] iv, Key aesKey)
            throws GeneralSecurityException {
        Cipher cipher = CryptoIntegration.getProvider().getAesGcmCipher();
        GCMParameterSpec gcmParams = new GCMParameterSpec(AUTH_TAG_SIZE_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParams);
        byte[] cipherText = cipher.doFinal(contentBytes);
        // store iv
        byte[] result = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);
        return result;
    }

    private static byte[] decryptBytes(byte[] ivAndCiphertext, Key aesKey) throws GeneralSecurityException {
        Cipher cipher = CryptoIntegration.getProvider().getAesGcmCipher();
        GCMParameterSpec gcmParams = new GCMParameterSpec(AUTH_TAG_SIZE_BITS, ivAndCiphertext, 0, IV_SIZE_BYTE);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParams);
        return cipher.doFinal(ivAndCiphertext, IV_SIZE_BYTE, ivAndCiphertext.length - IV_SIZE_BYTE);
    }


}
