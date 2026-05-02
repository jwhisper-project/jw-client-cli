package io.github.artshp.jwhisper.client.cli;

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Optional;

@Slf4j
public class CertUtils {

    private static final String CERTIFICATE_TYPE = "X.509";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String SSL_PROTOCOL = "TLSv1.3";

    private static final CertificateFactory CERTIFICATE_FACTORY;

    static {
        try {
            CERTIFICATE_FACTORY = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static Optional<X509Certificate> parsePemCertificate(String pem) {
        String cleanedPem = pem.strip()
                .replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
                .replace("-----END CERTIFICATE-----", "-----END CERTIFICATE-----\n");

        try (InputStream is = new ByteArrayInputStream(cleanedPem.getBytes())) {
            return Optional.of((X509Certificate) CERTIFICATE_FACTORY.generateCertificate(is));
        } catch (IOException | CertificateException e) {
            log.error("Failed to parse PEM certificate", e);
            return Optional.empty();
        }
    }

    public static String getFingerprint(X509Certificate certificate) {
        byte[] data;
        try {
            data = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            log.error("Failed to encode certificate", e);
            return null;
        }

        return getFingerprint(data);
    }

    public static String getFingerprint(PublicKey key) {
        return getFingerprint(key.getEncoded());
    }

    public static String getFingerprint(byte[] data) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            log.error("{} is not available.", HASH_ALGORITHM);
            throw new IllegalStateException(HASH_ALGORITHM + " is not available.", e);
        }

        byte[] hash = md.digest(data);
        String hex = HexFormat.of()
                .withPrefix(":")
                .withUpperCase()
                .formatHex(hash);

        return HASH_ALGORITHM + hex;
    }
}
