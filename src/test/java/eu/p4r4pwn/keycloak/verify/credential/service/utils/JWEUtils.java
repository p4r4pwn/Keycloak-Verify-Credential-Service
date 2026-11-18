package eu.p4r4pwn.keycloak.verify.credential.service.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class JWEUtils {
    private static PublicKey encryptionKey;

    static {
        try {
            encryptionKey = loadEncryptionKey();
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static PublicKey loadEncryptionKey() throws CertificateException {
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate;

        try (InputStream is = JWEUtils.class.getResourceAsStream("/keys/test-cert.pem")) {
            certificate = (X509Certificate)factory.generateCertificate(is);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return  certificate.getPublicKey();
    }

    public static String encryptContent(final String value) {
        final KeyAlgorithm<PublicKey, ?> keyAlgorithm = Jwts.KEY.RSA_OAEP_256;
        final AeadAlgorithm encryptionAlgorithm = Jwts.ENC.A256GCM;

        return Jwts.builder()
                .content(value.getBytes(StandardCharsets.UTF_8))
                .encryptWith(encryptionKey, keyAlgorithm, encryptionAlgorithm)
                .compact();

    }
}
