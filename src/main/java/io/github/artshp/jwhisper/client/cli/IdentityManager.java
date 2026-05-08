package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.exception.WrongPasswordException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

@Slf4j
class IdentityManager {

    private static final String KEY_ALIAS = "jwhisper-id";
    private static final String KEYSTORE_FILE = "identity.p12";
    private static final Path KEYSTORE_FILE_PATH = Path.of(KEYSTORE_FILE);

    public static boolean isKeyStoreAvailable() {
        return Files.exists(KEYSTORE_FILE_PATH);
    }

    public static KeyPair loadKeys(char[] password) throws WrongPasswordException {
        log.info("Trying to load existing key store from file \"{}\"", KEYSTORE_FILE_PATH);

        KeyStore keyStore = SecurityUtils.createAndLoadKeyStore(password, KEYSTORE_FILE_PATH);
        try {
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, password);
            Certificate certificate = keyStore.getCertificate(KEY_ALIAS);

            return new KeyPair(certificate.getPublicKey(), privateKey);
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            log.error("Failed to load keys from key store", e);
            throw new RuntimeException("Failed to load keys from key store", e);
        }
    }

    public static KeyPair createKeys(char[] password, String username) {
        log.info("Key store file \"{}\" does not exist. Creating a new one", KEYSTORE_FILE_PATH);

        KeyStore keyStore = SecurityUtils.createAndLoadEmptyKeyStore();
        KeyPair keyPair = SecurityUtils.KEY_PAIR_GENERATOR.generateKeyPair();
        X509Certificate certificate = generateSelfSignedCertificate(keyPair, username);
        try {
            keyStore.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), password, new X509Certificate[]{certificate});
        } catch (KeyStoreException e) {
            log.error("Failed to set key entry for {}.", KEY_ALIAS, e);
            throw new RuntimeException("Failed to set key entry for " + KEY_ALIAS, e);
        }

        SecurityUtils.saveKeyStore(keyStore, password, KEYSTORE_FILE_PATH);
        return keyPair;
    }

    private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String username) {
        final long now = System.currentTimeMillis();
        X509v3CertificateBuilder certificateBuilder = getX509v3CertificateBuilder(keyPair, username, now);

        try {
            // Sign it using the private key
            ContentSigner contentSigner = new JcaContentSignerBuilder(SecurityUtils.USER_KEYS_ALGORITHM)
                    .setProvider(SecurityUtils.BOUNCY_CASTLE_PROVIDER)
                    .build(keyPair.getPrivate());

            X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
            return new JcaX509CertificateConverter()
                    .setProvider(SecurityUtils.BOUNCY_CASTLE_PROVIDER)
                    .getCertificate(certificateHolder);
        } catch (OperatorCreationException | CertificateException e) {
            log.error("Failed to generate self signed certificate.", e);
            throw new RuntimeException("Failed to generate self signed certificate.", e);
        }
    }

    private static X509v3CertificateBuilder getX509v3CertificateBuilder(
            KeyPair keyPair, String username, long now
    ) {
        Date startDate = new Date(now);

        // Create the certificate's subject and issuer (same for self-signed)
        X500Name name = new X500Name("CN=" + username);
        BigInteger certificateSerialNumber = BigInteger.valueOf(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year validity

        // Build the certificate
        return new JcaX509v3CertificateBuilder(
                name, certificateSerialNumber, startDate, endDate, name, keyPair.getPublic()
        );
    }
}
