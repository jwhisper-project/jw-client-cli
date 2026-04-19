package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.client.cli.exception.WrongPasswordException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Optional;

@Slf4j
class IdentityManager {

    private static final String PROVIDER = "BC"; // Bouncy Castle
    private static final String KEY_STORE_TYPE = "PKCS12";
    private static final String USER_KEYS_ALGORITHM = "Ed25519";

    private static final String KEY_ALIAS = "jwhisper-id";
    private static final String KEYSTORE_FILE = "identity.p12";
    private static final Path KEYSTORE_FILE_PATH = Path.of(KEYSTORE_FILE);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static KeyStore getKeyStore() {
        try {
            return KeyStore.getInstance(KEY_STORE_TYPE);
        } catch (KeyStoreException e) {
            log.error("Key Store type {} is not supported.", KEY_STORE_TYPE, e);
            throw new IllegalStateException("Key Store type is not supported.", e);
        }
    }

    private static KeyPairGenerator getKeyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance(USER_KEYS_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            log.error("Key Gen algorithm {} is not supported.", USER_KEYS_ALGORITHM, e);
            throw new IllegalStateException("Key Gen algorithm is not supported.", e);
        }
    }

    public static boolean isKeyStoreAvailable() {
        return Files.exists(KEYSTORE_FILE_PATH);
    }

    public static KeyPair loadKeys(char[] password) throws WrongPasswordException {
        KeyStore keyStore = getKeyStore();

        log.info("Trying to load existing key store from file \"{}\"", KEYSTORE_FILE_PATH);

        try (InputStream fis = Files.newInputStream(KEYSTORE_FILE_PATH)) {
            keyStore.load(fis, password);
        } catch (NoSuchAlgorithmException | CertificateException e) {
            log.error("Failed to load key store from file \"{}\"", KEYSTORE_FILE_PATH, e);
            throw new RuntimeException("Failed to load key store from file \"" + KEYSTORE_FILE_PATH + "\"", e);
        } catch (IOException e) {
            Class<?> causeClass = Optional.ofNullable(e.getCause())
                    .map(Throwable::getClass)
                    .orElse(null);

            // Was it caused by wrong password?
            if (UnrecoverableKeyException.class.equals(causeClass)) {
                throw new WrongPasswordException("Wrong password provided for key store", e);
            } else {
                throw new RuntimeException("Failed to load key store from file \"" + KEYSTORE_FILE_PATH + "\"", e);
            }
        }

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
        KeyStore keyStore = getKeyStore();

        log.info("Key store file \"{}\" does not exist. Creating a new one", KEYSTORE_FILE_PATH);

        KeyPairGenerator keyPairGenerator = getKeyPairGenerator();
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X509Certificate certificate = generateSelfSignedCertificate(keyPair, username);

        try {
            keyStore.load(null, null);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            log.error("Failed to initialize key store.", e);
            throw new RuntimeException("Failed to initialize key store", e);
        }

        try {
            keyStore.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), password, new X509Certificate[]{certificate});
        } catch (KeyStoreException e) {
            log.error("Failed to set key entry for {}.", KEY_ALIAS, e);
            throw new RuntimeException("Failed to set key entry for " + KEY_ALIAS, e);
        }

        try (OutputStream fos = Files.newOutputStream(KEYSTORE_FILE_PATH)) {
            keyStore.store(fos, password);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            log.error("Failed to persist key store to the file \"{}\"", KEYSTORE_FILE_PATH, e);
            throw new RuntimeException("Failed to persist key store to the file " + KEYSTORE_FILE_PATH + ".", e);
        }

        return keyPair;
    }

    private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String username) {
        final long now = System.currentTimeMillis();
        X509v3CertificateBuilder certificateBuilder = getX509v3CertificateBuilder(keyPair, username, now);

        try {
            // Sign it using the private key
            ContentSigner contentSigner = new JcaContentSignerBuilder(USER_KEYS_ALGORITHM)
                    .setProvider(PROVIDER)
                    .build(keyPair.getPrivate());

            X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
            return new JcaX509CertificateConverter()
                    .setProvider(PROVIDER)
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
