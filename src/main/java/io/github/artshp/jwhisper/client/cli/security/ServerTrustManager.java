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

@Slf4j
public class ServerTrustManager {

    private static final String TRUSTSTORE_FILE = "truststore.p12";
    private static final Path TRUSTSTORE_FILE_PATH = Path.of(TRUSTSTORE_FILE);

    private final char[] password;
    private final KeyStore trustStore;

    public ServerTrustManager(char[] password) {
        this.password = password;

        if (Files.exists(TRUSTSTORE_FILE_PATH)) {
            log.debug("Loading truststore from {}", TRUSTSTORE_FILE_PATH);
            trustStore = SecurityUtils.createAndLoadKeyStore(password, TRUSTSTORE_FILE_PATH);
        } else {
            log.debug("Creating new truststore");
            trustStore = SecurityUtils.createAndLoadEmptyKeyStore();
            saveTrustStore();
        }
    }

    public void addTrustedCertificate(X509Certificate certificate) {
        try {
            trustStore.setCertificateEntry(UUID.randomUUID().toString(), certificate);
        } catch (KeyStoreException e) {
            log.error("Failed to set trusted certificate", e);
            return;
        }

        saveTrustStore();
        log.info("Trusted certificate with fingerprint {} added", CertUtils.getFingerprint(certificate));
    }

    public SSLSocketFactory getSSLSocketFactory() {
        try {
            TrustManagerFactory tmf = SecurityUtils.newTrustManagerFactory();
            SSLContext ctx = SSLContext.getInstance(SecurityUtils.SSL_PROTOCOL);

            tmf.init(trustStore);
            ctx.init(null, tmf.getTrustManagers(), null);

            return ctx.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            log.error("Failed to initialize SSL context", e);
            throw new RuntimeException("Failed to initialize SSL context", e);
        }
    }

    private void saveTrustStore() {
        SecurityUtils.saveKeyStore(trustStore, password, TRUSTSTORE_FILE_PATH);
    }
}
