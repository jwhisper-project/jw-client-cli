package io.github.artshp.jwhisper.client.cli.security;

import io.github.artshp.jwhisper.common.crypto.CertUtils;
import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.UUID;

/**
 * Manager responsible for certificates of trusted relay servers.
 */
@Slf4j
public class ServerTrustManager {

    /**
     * Filename of key store with trusted servers' certificates
     */
    private static final String TRUSTSTORE_FILE = "truststore.p12";

    /**
     * Path to key store with trusted servers' certificates
     */
    private static final Path TRUSTSTORE_FILE_PATH = Path.of(TRUSTSTORE_FILE);

    /**
     * Key store password
     */
    private final char[] password;

    /**
     * Key store with trusted servers' certificates
     */
    private final KeyStore trustStore;

    /**
     * Create a new server trust manager.
     * @param password password to key store
     */
    public ServerTrustManager(char[] password) {
        this.password = password;

        if (Files.exists(TRUSTSTORE_FILE_PATH)) {
            LOGGER.debug("Loading truststore from {}", TRUSTSTORE_FILE_PATH);
            trustStore = SecurityUtils.createAndLoadKeyStore(password, TRUSTSTORE_FILE_PATH);
        } else {
            LOGGER.debug("Creating new truststore");
            trustStore = SecurityUtils.createAndLoadEmptyKeyStore();
            saveTrustStore();
        }
    }

    /**
     * Add a new trusted certificate to trust store.
     * @param certificate certificate to be trusted
     */
    public void addTrustedCertificate(X509Certificate certificate) {
        try {
            trustStore.setCertificateEntry(UUID.randomUUID().toString(), certificate);
        } catch (KeyStoreException e) {
            LOGGER.error("Failed to set trusted certificate", e);
            return;
        }

        saveTrustStore();
        LOGGER.info("Trusted certificate with fingerprint {} added", CertUtils.getFingerprint(certificate));
    }

    /**
     * Generate SSL socket factory trusting only to the white list of certificates/servers.
     * @return generated SSL socket factory
     */
    public SSLSocketFactory getSSLSocketFactory() {
        try {
            TrustManagerFactory tmf = SecurityUtils.newTrustManagerFactory();
            SSLContext ctx = SSLContext.getInstance(SecurityUtils.SSL_PROTOCOL);

            tmf.init(trustStore);
            ctx.init(null, tmf.getTrustManagers(), null);

            return ctx.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            LOGGER.error("Failed to initialize SSL context", e);
            throw new RuntimeException("Failed to initialize SSL context", e);
        }
    }

    /**
     * Persist trust store.
     */
    private void saveTrustStore() {
        SecurityUtils.saveKeyStore(trustStore, password, TRUSTSTORE_FILE_PATH);
    }
}
