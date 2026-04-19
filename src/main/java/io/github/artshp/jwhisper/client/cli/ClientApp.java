package io.github.artshp.jwhisper.client.cli;

import lombok.extern.slf4j.Slf4j;

import java.io.Console;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HexFormat;

/**
 * Client app class.
 */
@Slf4j
class ClientApp {

    private static final String HASH_ALGORITHM = "SHA-256";

    private final Console console;

    /**
     * Constructs a new client application.
     */
    public ClientApp() {
        console = System.console();
        if (console == null) {
            log.error("Console is not available.");
            throw new IllegalStateException("Console is not available.");
        }
    }

    /**
     * Start client application.
     */
    public void start() {
        log.info("Starting Client App");
        System.out.println("----- JWhisper Client -----");

        KeyPair keyPair;
        if (IdentityManager.isKeyStoreAvailable()) {
            log.info("Key Store is available. Trying to load it...");

            char[] password = readPassword();
            keyPair = IdentityManager.loadKeys(password);
        } else {
            log.info("Key Store is not available. Creating it...");

            char[] password = readPassword();
            String username = readUsername();
            keyPair = IdentityManager.createKeys(password, username);
        }

        log.info("Identity loaded. Fingerprint: {}", calculateFingerprint(keyPair.getPublic()));
    }

    private char[] readPassword() {
        return console.readPassword("Enter Password: ");
    }

    private String readUsername() {
        return console.readLine("Enter Username: ");
    }

    private static String calculateFingerprint(PublicKey key) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            log.error("{} is not available.", HASH_ALGORITHM);
            throw new IllegalStateException(HASH_ALGORITHM + " is not available.", e);
        }

        byte[] hash = md.digest(key.getEncoded());
        String hex = HexFormat.of()
                .withPrefix(":")
                .withUpperCase()
                .formatHex(hash);

        return HASH_ALGORITHM + hex;
    }
}
