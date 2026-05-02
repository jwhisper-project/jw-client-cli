package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.client.cli.exception.WrongPasswordException;
import lombok.extern.slf4j.Slf4j;

import java.io.Console;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

/**
 * Client app class.
 */
@Slf4j
class ClientApp {

    private final Console console;
    private final ConfigManager configManager = new ConfigManager();

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

        log.info("Identity loaded. Fingerprint: {}", CertUtils.getFingerprint(keyPair.getPublic()));

        ClientConfig config;
        if (!configManager.isConfigPresent()) {
            log.debug("No config present. Creating it...");

            String hostname = readHostname();
            int port = readPort();

            config = new ClientConfig(hostname, port);
            configManager.saveConfig(config);
        } else {
            log.debug("Config present. Loading it...");
            config = configManager.loadConfig();
        }

        log.info("Used config: {}", config.toPrettyString());

        // TODO: replace with real password
        ServerTrustManager serverTrustManager = new ServerTrustManager("changeit".toCharArray());

        if (askYesNo("Do you want to add server's certificate?")) {
            Optional<X509Certificate> certificateOptional = readCertificate();
            if (certificateOptional.isEmpty()) {
                log.error("Failed to load certificate.");
                return;
            }

            X509Certificate certificate = certificateOptional.get();
            serverTrustManager.addTrustedCertificate(certificate);
        }

        try (NetworkClient client = new NetworkClient(serverTrustManager, config.hostname(), config.port())) {
            client.connect();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean askYesNo(String question) {
        String answer = console.readLine(question + " (Y/n): ");

        return answer.equalsIgnoreCase("y") || answer.equalsIgnoreCase("yes");
    }

    private Optional<X509Certificate> readCertificate() {
        String cert = console.readLine("Enter certificate (single line, with PEM boundaries): ");
        return CertUtils.parsePemCertificate(cert);
    }

    private String readHostname() {
        String hostname = console.readLine("Enter hostname: ");
        return hostname.isEmpty() ? "localhost" : hostname;
    }

    private int readPort() {
        String portString = console.readLine("Enter port: ");
        return portString.isEmpty() ? 8080 : Integer.parseInt(portString);
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
}
