package io.github.artshp.jwhisper.client.cli.security;

import io.github.artshp.jwhisper.common.crypto.SecurityUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;

public class MessageCrypto {

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private static final SecureRandom RANDOM = new SecureRandom();

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
        byte[] ciphertext = cipher.doFinal(plainText);

        return new Sealed(ephemeral.getPublic().getEncoded(), nonce, ciphertext);
    }

    public static byte[] decrypt(PrivateKey myEncryptionKey, byte[] ephemeralPublicKey, byte[] nonce, byte[] cipherText)
            throws GeneralSecurityException {
        PublicKey senderEphemeral = SecurityUtils.newEncryptionPublicKey(ephemeralPublicKey);
        byte[] sharedSecret = deriveSharedSecret(myEncryptionKey, senderEphemeral);
        byte[] aesKey = deriveAesKey(sharedSecret);

        Cipher cipher = SecurityUtils.newCipher();
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(aesKey, ENCRYPTION_ALGORITHM),
                new GCMParameterSpec(GCM_TAG_LENGTH, nonce)
        );

        return cipher.doFinal(cipherText);
    }

    public static byte[] signedPayload(byte[] ephemeralPublicKey, byte[] nonce, byte[] cipherText) {
        return ByteBuffer.allocate(ephemeralPublicKey.length + nonce.length + cipherText.length)
                .put(ephemeralPublicKey)
                .put(nonce)
                .put(cipherText)
                .array();
    }

    private static byte[] deriveSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance(SecurityUtils.ENCRYPTION_ALGORITHM);

        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);

        return agreement.generateSecret();
    }

    private static byte[] deriveAesKey(byte[] sharedSecret) {
        return SecurityUtils.MESSAGE_DIGEST.digest(sharedSecret);
    }

    private static KeyPair generateEphemeralKeyPair() {
        return SecurityUtils.ENCRYPTION_KEY_PAIR_GENERATOR.generateKeyPair();
    }

    public record Sealed(byte[] ephemeralPublicKey, byte[] nonce, byte[] cipherText) {
    }
}
