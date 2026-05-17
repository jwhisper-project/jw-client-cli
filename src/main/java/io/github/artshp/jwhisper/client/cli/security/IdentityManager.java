package io.github.artshp.jwhisper.client.cli.security;

import io.github.artshp.jwhisper.client.cli.users.UserKeys;
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

/**
 * Client identity manager. Responsible for client signing and encryption keys.
 */
@Slf4j
public final class IdentityManager {

    /**
     * Signing key alias in key store.
     */
    private static final String SIGNING_KEY_ALIAS = "jwhisper-sign";

    /**
     * Encryption key alias in key store.
     */
    private static final String ENCRYPTION_KEY_ALIAS = "jwhisper-encrypt";

    /**
     * Filename of key store with client keys
     */
    private static final String KEYSTORE_FILE = "identity.p12";

    /**
     * Path to key store with client keys
     */
    private static final Path KEYSTORE_FILE_PATH = Path.of(KEYSTORE_FILE);

    /**
     * Does key store file exist?
     * @return {@code true} if key store file exists, otherwise {@code false}
     */
    public static boolean isKeyStoreAvailable() {
        return Files.exists(KEYSTORE_FILE_PATH);
    }

    /**
     * Load client keys.
     * @param password password to key store
     * @return user keys
     * @throws WrongPasswordException if wrong password provided
     */
    public static UserKeys loadKeys(char[] password) throws WrongPasswordException {
        LOGGER.info("Trying to load existing key store from file \"{}\"", KEYSTORE_FILE_PATH);

        KeyStore keyStore = SecurityUtils.createAndLoadKeyStore(password, KEYSTORE_FILE_PATH);
        try {
            KeyPair signing = loadKeyPair(keyStore, SIGNING_KEY_ALIAS, password);
            KeyPair encryption = loadKeyPair(keyStore, ENCRYPTION_KEY_ALIAS, password);
            return new UserKeys(signing, encryption);
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            LOGGER.error("Failed to load keys from key store", e);
            throw new RuntimeException("Failed to load keys from key store", e);
        }
    }

    /**
     * Create client keys.
     * @param password password to be used for truststore
     * @param username username to be used for certificate generation
     * @return user keys
     */
    public static UserKeys createKeys(char[] password, String username) {
        LOGGER.info("Key store file \"{}\" does not exist. Creating a new one", KEYSTORE_FILE_PATH);

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
            LOGGER.error("Failed to set key entries in key store.", e);
            throw new RuntimeException("Failed to set key entries in key store", e);
        }

        SecurityUtils.saveKeyStore(keyStore, password, KEYSTORE_FILE_PATH);
        return new UserKeys(signing, encryption);
    }

    /**
     * Load key pair from given key store.
     * @param keyStore key store to load key pair from
     * @param alias key pair alias
     * @param password key store password
     * @return loaded key pair
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws KeyStoreException if the keystore has not been initialized
     * @throws UnrecoverableKeyException if the key cannot be recovered (e.g., the given password is wrong)
     */
    private static KeyPair loadKeyPair(KeyStore keyStore, String alias, char[] password)
            throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        Certificate certificate = keyStore.getCertificate(alias);
        return new KeyPair(certificate.getPublicKey(), privateKey);
    }

    /**
     * Generate self-signed {@code X509} certificate.
     * @param subjectPublicKey public key for certificate
     * @param signingKey private key for certificate
     * @param username username for certificate
     * @return generated certificate
     */
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
            LOGGER.error("Failed to generate certificate.", e);
            throw new RuntimeException("Failed to generate certificate.", e);
        }
    }

    /**
     * Create {@code X509} certificate builder.
     * @param subjectPublicKey public key for certificate
     * @param username username for certificate
     * @param now current time in UNIX format
     * @return certificate builder
     */
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

    /**
     * Constructor to prohibit instantiating.
     */
    private IdentityManager() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }
}
