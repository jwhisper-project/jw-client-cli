package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.common.crypto.CertUtils;
import io.github.artshp.jwhisper.common.crypto.PasswordUtils;
import io.github.artshp.jwhisper.common.exception.InputRetryException;
import io.github.artshp.jwhisper.common.exception.NetworkServiceException;
import io.github.artshp.jwhisper.common.exception.WrongPasswordException;
import io.github.artshp.jwhisper.common.io.UserInputUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Client app class.
 */
@Slf4j
class ClientApp {

    private final ConfigManager configManager = new ConfigManager();

    /**
     * Constructs a new client application.
     */
    public ClientApp() {
    }

    /**
     * Start client application.
     */
    public void start() throws InputRetryException, NetworkServiceException {
        log.info("Starting Client App");
        System.out.println("----- JWhisper Client -----");

        String username = UserInputUtils.readUsername();

        UserKeys keys;
        char[] password;
        if (IdentityManager.isKeyStoreAvailable()) {
            log.info("Key Store is available. Trying to load it...");

            password = UserInputUtils.readPassword();
            try {
                keys = IdentityManager.loadKeys(password);
            } catch (WrongPasswordException e) {
                log.error("Wrong password provided.");
                return;
            }
        } else {
            log.info("Key Store is not available. Creating it...");

            password = UserInputUtils.readNewPassword();
            keys = IdentityManager.createKeys(password, username);
        }

        log.info("Identity loaded. Signing key fingerprint: {}",
                CertUtils.getFingerprint(keys.signing().getPublic())
        );
        log.info("Encryption key fingerprint: {}",
                CertUtils.getFingerprint(keys.encryption().getPublic())
        );

        ClientConfig config;
        if (!configManager.isConfigPresent()) {
            log.debug("No config present. Creating it...");

            String hostname = UserInputUtils.readHostname();
            int port = UserInputUtils.readPort();

            config = new ClientConfig(hostname, port);
            configManager.saveConfig(config);
        } else {
            log.debug("Config present. Loading it...");
            config = configManager.loadConfig();
        }

        log.info("Used config: {}", config.toPrettyString());

        ServerTrustManager serverTrustManager = new ServerTrustManager(password);
        if (UserInputUtils.askYesNo("Do you want to add server's certificate?")) {
            Optional<X509Certificate> certificateOptional = UserInputUtils.readCertificate();
            if (certificateOptional.isEmpty()) {
                log.error("Failed to load certificate.");
                return;
            }

            X509Certificate certificate = certificateOptional.get();
            serverTrustManager.addTrustedCertificate(certificate);
        }
        password = PasswordUtils.cleanPassword(password);

        try (NetworkClient client = new NetworkClient(serverTrustManager, config.hostname(), config.port())) {
            client.connect();
            if (!client.register(username, keys)) {
                throw new NetworkServiceException("Failed to register your user.");
            }

            CommunicationManager communicationManager = new CommunicationManager(
                    username,
                    keys,
                    client
            );
            communicationManager.start();

            log.info("Goodbye!");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
