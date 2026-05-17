package io.github.artshp.jwhisper.client.cli.security;

import io.github.artshp.jwhisper.common.crypto.SecurityUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;

/**
 * Service responsible for messages encryption/decryption.
 */
public final class MessageCrypto {

    /**
     * Algorithm used for end-to-end messages encryption.
     */
    private static final String ENCRYPTION_ALGORITHM = "AES";

    /**
     * Length of nonce used for end-to-end encryption.
     */
    private static final int NONCE_LENGTH = 12;

    /**
     * Length og GCM tag used for end-to-end encryption.
     */
    private static final int GCM_TAG_LENGTH = 128;

    /**
     * Secure random provider.
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Encrypt raw message bytes addressed to specific recipient.
     * @param recipientEncryptionKey recipient's public encryption key
     * @param plainText raw message bytes
     * @return encrypted package
     * @throws GeneralSecurityException if error occurred during encryption
     */
    public static Sealed encrypt(PublicKey recipientEncryptionKey, byte[] plainText)
            throws GeneralSecurityException {
        KeyPair ephemeral = generateEphemeralKeyPair();
        byte[] sharedSecret = deriveSharedSecret(ephemeral.getPrivate(), recipientEncryptionKey);
        byte[] aesKey = deriveAesKey(sharedSecret);

        byte[] nonce = new byte[NONCE_LENGTH];
        RANDOM.nextBytes(nonce);

        Cipher cipher = SecurityUtils.newCipher();
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(aesKey, ENCRYPTION_ALGORITHM),
                new GCMParameterSpec(GCM_TAG_LENGTH, nonce)
        );
        byte[] cipherText = cipher.doFinal(plainText);

        return new Sealed(ephemeral.getPublic().getEncoded(), nonce, cipherText);
    }

    /**
     * Decrypt encrypted message bytes addressed to specific recipient.
     * @param myEncryptionKey recipient's private encryption key
     * @param sealed encrypted package
     * @return decrypted raw message bytes
     * @throws GeneralSecurityException if error occurred during decryption
     */
    public static byte[] decrypt(PrivateKey myEncryptionKey, Sealed sealed)
            throws GeneralSecurityException {
        PublicKey senderEphemeral = SecurityUtils.newEncryptionPublicKey(sealed.ephemeralPublicKey);
        byte[] sharedSecret = deriveSharedSecret(myEncryptionKey, senderEphemeral);
        byte[] aesKey = deriveAesKey(sharedSecret);

        Cipher cipher = SecurityUtils.newCipher();
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(aesKey, ENCRYPTION_ALGORITHM),
                new GCMParameterSpec(GCM_TAG_LENGTH, sealed.nonce)
        );

        return cipher.doFinal(sealed.cipherText);
    }

    /**
     * Create payload for signature from encrypted package.
     * @param sealed encrypted package
     * @return computed payload (raw bytes)
     */
    public static byte[] signedPayload(Sealed sealed) {
        return ByteBuffer.allocate(sealed.ephemeralPublicKey.length + sealed.nonce.length + sealed.cipherText.length)
                .put(sealed.ephemeralPublicKey)
                .put(sealed.nonce)
                .put(sealed.cipherText)
                .array();
    }

    /**
     * Derive shared secret for end-to-end encryption between clients.
     * @param privateKey private key
     * @param publicKey public key
     * @return derived shared secret
     * @throws GeneralSecurityException if error occurred during shared secret derivation
     */
    private static byte[] deriveSharedSecret(PrivateKey privateKey, PublicKey publicKey)
            throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance(SecurityUtils.ENCRYPTION_ALGORITHM);

        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);

        return agreement.generateSecret();
    }

    /**
     * Derive {@code AES} key from shared secret computing its fingerprint.
     * @param sharedSecret shared secret
     * @return derived {@code AES} key
     */
    private static byte[] deriveAesKey(byte[] sharedSecret) {
        return SecurityUtils.MESSAGE_DIGEST.digest(sharedSecret);
    }

    /**
     * Generate ephemeral key pair for end-to-end encryption of messages.
     * @return generated key pair
     */
    private static KeyPair generateEphemeralKeyPair() {
        return SecurityUtils.ENCRYPTION_KEY_PAIR_GENERATOR.generateKeyPair();
    }

    /**
     * Encrypted message package.
     * @param ephemeralPublicKey ephemeral public key
     * @param nonce nonce
     * @param cipherText encrypted message
     */
    public record Sealed(
            byte[] ephemeralPublicKey,
            byte[] nonce,
            byte[] cipherText
    ) {
    }

    /**
     * Constructor to prohibit instantiating.
     */
    private MessageCrypto() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }
}
