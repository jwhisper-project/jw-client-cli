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

    private static final String SIGNING_KEY_ALIAS = "jwhisper-sign";
    private static final String ENCRYPTION_KEY_ALIAS = "jwhisper-encrypt";
    private static final String KEYSTORE_FILE = "identity.p12";
    private static final Path KEYSTORE_FILE_PATH = Path.of(KEYSTORE_FILE);

    public static boolean isKeyStoreAvailable() {
        return Files.exists(KEYSTORE_FILE_PATH);
    }

    public static UserKeys loadKeys(char[] password) throws WrongPasswordException {
        log.info("Trying to load existing key store from file \"{}\"", KEYSTORE_FILE_PATH);

        KeyStore keyStore = SecurityUtils.createAndLoadKeyStore(password, KEYSTORE_FILE_PATH);
        try {
            KeyPair signing = loadKeyPair(keyStore, SIGNING_KEY_ALIAS, password);
            KeyPair encryption = loadKeyPair(keyStore, ENCRYPTION_KEY_ALIAS, password);
            return new UserKeys(signing, encryption);
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            log.error("Failed to load keys from key store", e);
            throw new RuntimeException("Failed to load keys from key store", e);
        }
    }

    private static KeyPair loadKeyPair(KeyStore keyStore, String alias, char[] password)
            throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        Certificate certificate = keyStore.getCertificate(alias);
        return new KeyPair(certificate.getPublicKey(), privateKey);
    }

    public static UserKeys createKeys(char[] password, String username) {
        log.info("Key store file \"{}\" does not exist. Creating a new one", KEYSTORE_FILE_PATH);

        KeyStore keyStore = SecurityUtils.createAndLoadEmptyKeyStore();

        KeyPair signing = SecurityUtils.SIGNING_KEY_PAIR_GENERATOR.generateKeyPair();
        KeyPair encryption = SecurityUtils.ENCRYPTION_KEY_PAIR_GENERATOR.generateKeyPair();

        X509Certificate signingCert = generateCertificate(signing.getPublic(), signing.getPrivate(), username);
        X509Certificate encryptionCert = generateCertificate(encryption.getPublic(), signing.getPrivate(), username);

        try {
            keyStore.setKeyEntry(
                    SIGNING_KEY_ALIAS,
                    signing.getPrivate(),
                    password,
                    new X509Certificate[]{signingCert}
            );
            keyStore.setKeyEntry(
                    ENCRYPTION_KEY_ALIAS,
                    encryption.getPrivate(),
                    password,
                    new X509Certificate[]{encryptionCert}
            );
        } catch (KeyStoreException e) {
            log.error("Failed to set key entries in key store.", e);
            throw new RuntimeException("Failed to set key entries in key store", e);
        }

        SecurityUtils.saveKeyStore(keyStore, password, KEYSTORE_FILE_PATH);
        return new UserKeys(signing, encryption);
    }

    private static X509Certificate generateCertificate(PublicKey subjectPublicKey, PrivateKey signingKey, String username) {
        final long now = System.currentTimeMillis();
        X509v3CertificateBuilder certificateBuilder = getX509v3CertificateBuilder(subjectPublicKey, username, now);

        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(SecurityUtils.SIGNING_ALGORITHM)
                    .setProvider(SecurityUtils.BOUNCY_CASTLE_PROVIDER)
                    .build(signingKey);

            X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
            return new JcaX509CertificateConverter()
                    .setProvider(SecurityUtils.BOUNCY_CASTLE_PROVIDER)
                    .getCertificate(certificateHolder);
        } catch (OperatorCreationException | CertificateException e) {
            log.error("Failed to generate certificate.", e);
            throw new RuntimeException("Failed to generate certificate.", e);
        }
    }

    private static X509v3CertificateBuilder getX509v3CertificateBuilder(
            PublicKey subjectPublicKey, String username, long now
    ) {
        Date startDate = new Date(now);
        X500Name name = new X500Name("CN=" + username);
        BigInteger certificateSerialNumber = BigInteger.valueOf(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000);

        return new JcaX509v3CertificateBuilder(
                name, certificateSerialNumber, startDate, endDate, name, subjectPublicKey
        );
    }
}
