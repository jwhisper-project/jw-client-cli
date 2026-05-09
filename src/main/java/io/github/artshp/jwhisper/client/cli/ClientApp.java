package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.common.crypto.CertUtils;
import io.github.artshp.jwhisper.common.exception.InputRetryException;
import io.github.artshp.jwhisper.common.exception.NetworkServiceException;
import io.github.artshp.jwhisper.common.exception.WrongPasswordException;
import io.github.artshp.jwhisper.common.io.ConsoleUtils;
import io.github.artshp.jwhisper.common.io.UserInputUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.KeyPair;
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

        KeyPair keyPair;
        if (IdentityManager.isKeyStoreAvailable()) {
            log.info("Key Store is available. Trying to load it...");

            char[] password = UserInputUtils.readPassword();
            try {
                keyPair = IdentityManager.loadKeys(password);
            } catch (WrongPasswordException e) {
                log.error("Wrong password provided.");
                return;
            }
        } else {
            log.info("Key Store is not available. Creating it...");

            char[] password = UserInputUtils.readNewPassword();
            keyPair = IdentityManager.createKeys(password, username);
        }

        log.info("Identity loaded. Fingerprint: {}", CertUtils.getFingerprint(keyPair.getPublic()));

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

        // TODO: replace with real password
        ServerTrustManager serverTrustManager = new ServerTrustManager("changeit".toCharArray());

        if (UserInputUtils.askYesNo("Do you want to add server's certificate?")) {
            Optional<X509Certificate> certificateOptional = UserInputUtils.readCertificate();
            if (certificateOptional.isEmpty()) {
                log.error("Failed to load certificate.");
                return;
            }

            X509Certificate certificate = certificateOptional.get();
            serverTrustManager.addTrustedCertificate(certificate);
        }

        try (NetworkClient client = new NetworkClient(serverTrustManager, config.hostname(), config.port())) {
            client.connect();
            if (!client.register(username, keyPair)) {
                throw new NetworkServiceException("Failed to register your user.");
            }

            String message;
            do {
                message = ConsoleUtils.readString("Mock chat: ", _ -> true, null, 1);
            } while (!"quit".equals(message));

            if (!client.unregister(username)) {
                throw new NetworkServiceException("Failed to unregister your user.");
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
