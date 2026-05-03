package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.common.crypto.CertUtils;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;

@Slf4j
public class ServerTrustManager {

    private static final String TRUSTSTORE_FILE = "truststore.p12";
    private static final Path TRUSTSTORE_FILE_PATH = Path.of(TRUSTSTORE_FILE);
    private static final String SSL_PROTOCOL = "TLSv1.3";
    private static final String KEY_STORE_TYPE = "PKCS12";

    private final char[] password;
    private final KeyStore trustStore = getTrustStore();

    private static KeyStore getTrustStore() {
        try {
            return KeyStore.getInstance(KEY_STORE_TYPE);
        } catch (KeyStoreException e) {
            log.error("Key Store type {} is not supported.", KEY_STORE_TYPE, e);
            throw new IllegalStateException("Key Store type is not supported.", e);
        }
    }

    public ServerTrustManager(char[] password) {
        this.password = password;

        if (Files.exists(TRUSTSTORE_FILE_PATH)) {
            log.debug("Loading truststore from {}", TRUSTSTORE_FILE_PATH);

            try (InputStream fis = Files.newInputStream(TRUSTSTORE_FILE_PATH)) {
                trustStore.load(fis, password);
            } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
                log.error("Failed to load key store from file \"{}\"", TRUSTSTORE_FILE_PATH, e);
                throw new RuntimeException("Failed to load key store", e);
            }
        } else {
            try {
                trustStore.load(null, null);
                saveTrustStore();
            } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
                log.error("Failed to load key store from file \"{}\"", TRUSTSTORE_FILE_PATH, e);
                throw new RuntimeException("Failed to load key store", e);
            }
        }
    }

    public void addTrustedCertificate(X509Certificate certificate) {
        try {
            trustStore.setCertificateEntry(UUID.randomUUID().toString(), certificate);
            saveTrustStore();

            log.info("Trusted certificate with fingerprint {} added", CertUtils.getFingerprint(certificate));
        } catch (KeyStoreException e) {
            log.error("Failed to set trusted certificate \"{}\"", certificate, e);
        }
    }

    public SSLSocketFactory getSSLSocketFactory() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            SSLContext ctx = SSLContext.getInstance(SSL_PROTOCOL);

            tmf.init(trustStore);
            ctx.init(null, tmf.getTrustManagers(), null);

            return ctx.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            log.error("Failed to initialize SSL context", e);
            throw new RuntimeException("Failed to initialize SSL context", e);
        }
    }

    private void saveTrustStore() {
        try (OutputStream fos = Files.newOutputStream(TRUSTSTORE_FILE_PATH)) {
            trustStore.store(fos, password);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            log.error("Failed to save trust store to the file {}", TRUSTSTORE_FILE_PATH, e);
            throw new RuntimeException("Failed to save trust store", e);
        }
    }
}
