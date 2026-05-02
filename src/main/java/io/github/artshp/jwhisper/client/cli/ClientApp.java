package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.client.cli.exception.WrongPasswordException;
import lombok.extern.slf4j.Slf4j;

import java.io.Console;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;

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

            Optional<char[]> password = readPassword(false);
            if (password.isEmpty()) {
                log.error("Failed to get password.");
                return;
            }

            try {
                keyPair = IdentityManager.loadKeys(password.get());
            } catch (WrongPasswordException e) {
                log.error("Wrong password provided.");
                return;
            }
        } else {
            log.info("Key Store is not available. Creating it...");

            Optional<char[]> password = readPassword(true);
            if (password.isEmpty()) {
                log.error("Failed to get password.");
                throw new IllegalStateException("Failed to get password.");
            }

            Optional<String> username = readUsername();
            if (username.isEmpty()) {
                log.error("Failed to get username.");
                throw new IllegalStateException("Failed to get username.");
            }

            keyPair = IdentityManager.createKeys(password.get(), username.get());
        }

        log.info("Identity loaded. Fingerprint: {}", calculateFingerprint(keyPair.getPublic()));
    }

    private static boolean isPasswordValid(char[] password) {
        return password.length >= 4;
    }

    private Optional<char[]> readPassword(boolean repeat) {
        char[] password;

        boolean isValid;
        int i = 0;
        do {
            password = console.readPassword("Enter password: ");
            if (!isPasswordValid(password)) {
                isValid = false;
                log.warn("Password length should be at least 4. Try again.");
            } else {
                isValid = true;
            }

            i++;
        } while (!isValid && i < 3);

        if (!isValid) {
            log.error("Provided password is invalid.");
            return Optional.empty();
        }

        if (!repeat) {
            return Optional.of(password);
        }

        char[] passwordRetry;

        i = 0;
        do {
            passwordRetry = console.readPassword("Re-enter password: ");
            if (!Arrays.equals(password, passwordRetry)) {
                isValid = false;
                log.warn("Passwords are not equal. Try again.");
            } else {
                isValid = true;
            }

            i++;
        } while (!isValid && i < 3);

        if (!isValid) {
            log.warn("You failed to repeat the password.");
            return Optional.empty();
        }

        return Optional.of(password);
    }

    private static boolean isUsernameValid(String username) {
        return username.length() >= 4;
    }

    private Optional<String> readUsername() {
        String username;

        boolean isValid;
        int i = 0;
        do {
            username = console.readLine("Enter username: ").trim();
            if (!isUsernameValid(username)) {
                isValid = false;
                log.warn("Username length should be at least 4. Try again.");
            } else {
                isValid = true;
            }

            i++;
        } while (!isValid && i < 3);

        if (!isValid) {
            log.error("Provided username is invalid.");
            return Optional.empty();
        }

        return Optional.of(username);
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
