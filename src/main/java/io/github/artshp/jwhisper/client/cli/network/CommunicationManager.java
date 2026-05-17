package io.github.artshp.jwhisper.client.cli.network;

import io.github.artshp.jwhisper.client.cli.security.MessageCrypto;
import io.github.artshp.jwhisper.client.cli.users.UserKeys;
import io.github.artshp.jwhisper.client.cli.users.UserRegistry;
import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.exception.NetworkServiceException;
import io.github.artshp.jwhisper.common.io.ConsoleUtils;
import io.github.artshp.jwhisper.common.protocol.*;
import lombok.extern.slf4j.Slf4j;

import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.concurrent.*;

/**
 * Service responsible for double-ended network communication with relay.
 */
@Slf4j
public class CommunicationManager {

    /**
     * User's username.
     */
    private final String myUsername;

    /**
     * User's signing and encryption keys.
     */
    private final UserKeys myKeys;

    /**
     * Service responsible for sending messages over network.
     */
    private final NetworkClient client;

    /**
     * Service for caching information about other users.
     */
    private final UserRegistry userRegistry = new UserRegistry();

    /**
     * Future for unregister request.
     */
    private final CompletableFuture<StatusResponse> unregisterFuture = new CompletableFuture<>();

    /**
     * Listener thread, i.e. thread for incoming messages/responses from relay server.
     */
    private final Thread listenThread = Thread.ofVirtual()
            .name("listener")
            .unstarted(this::listenLoop);

    /**
     * Map of username to public keys fetch future.
     */
    private final Map<String, CompletableFuture<Void>> publicKeyFutures = new ConcurrentHashMap<>();

    /**
     * Flag for shutting down. Needed to normally finish listening loop.
     */
    private volatile boolean shuttingDown = false;

    /**
     * Create a new communication manager instance.
     * @param myUsername user's username
     * @param myKeys user's signing and encryption keys
     * @param client network service
     */
    public CommunicationManager(String myUsername, UserKeys myKeys, NetworkClient client) {
        this.myUsername = myUsername;
        this.myKeys = myKeys;
        this.client = client;
    }

    /**
     * Start double-ended communication with relay server.
     */
    public void start() {
        listenThread.start();
        uiLoop();
    }

    /**
     * Method responsible for all incoming messages.
     */
    private void listenLoop() {
        try {
            while (!shuttingDown) {
                WhisperMessage incoming = client.receive();

                switch (incoming) {
                    case EncryptedMessage message -> handleIncomingMessage(message);
                    case UserPublicKeyResponse publicKeyResponse -> handleKeyResponse(publicKeyResponse);
                    case StatusResponse statusResponse -> unregisterFuture.complete(statusResponse);
                    default -> LOGGER.warn("Unknown message received: {}", incoming);
                }
            }
        } catch (EOFException e) {
            if (shuttingDown) {
                LOGGER.debug("Listener stopped during shutdown.");
            } else {
                LOGGER.error("Connection lost.", e);
            }
        } catch (IOException e) {
            LOGGER.error("Connection lost.", e);
        } catch (Exception e) {
            LOGGER.error("Unexpected error occurred.", e);
        }
    }

    /**
     * Method responsible for all outcoming messages.
     */
    private void uiLoop() {
        LOGGER.info("Starting chat.");
        while (true) {
            try {
                String cmd = ConsoleUtils.readString("", _ -> true, null, 1);
                if (cmd.startsWith("/msg")) {
                    String[] parts = cmd.split(" ", 3);
                    sendDirectMessage(parts[1], parts[2]);
                } else if (cmd.startsWith("/exit")) {
                    LOGGER.info("Exiting.");
                    unregister();
                    return;
                }
            } catch (Exception e) {
                LOGGER.error("Command failed.", e);
            }
        }
    }

    /**
     * Send unregister request.
     * @throws IOException if failed to send request
     */
    private void unregister() throws IOException {
        UnregisterRequest request = new UnregisterRequest();
        client.send(request);

        StatusResponse response;
        try {
            response = unregisterFuture.get(5, TimeUnit.SECONDS);
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            LOGGER.error("Unregistering failed.", e);
            return;
        } finally {
            shuttingDown = true;
        }

        if (response.success()) {
            LOGGER.info("Successfully unregistered user {}", myUsername);
        } else {
            LOGGER.error("Failed to unregister user {}", myUsername);
        }
    }

    /**
     * Handle user public keys message from relay server.
     * @param response server's message/response
     */
    private void handleKeyResponse(UserPublicKeyResponse response) {
        String targetUsername = response.targetUsername();

        if (response.found()) {
            try {
                PublicKey signing = SecurityUtils.newSigningPublicKey(response.publicSigningKey());
                PublicKey encryption = SecurityUtils.newEncryptionPublicKey(response.publicEncryptionKey());
                userRegistry.addUserPublicKeys(targetUsername, signing, encryption);
                LOGGER.info("Successfully obtained public keys of user {}", targetUsername);
            } catch (InvalidKeySpecException e) {
                LOGGER.error("Failed to parse public keys of user {}", targetUsername, e);
                userRegistry.markUnavailable(targetUsername);
            }
        } else {
            LOGGER.error("Failed to obtain public keys of user {}", targetUsername);
            userRegistry.markUnavailable(targetUsername);
        }

        CompletableFuture<Void> future = publicKeyFutures.get(targetUsername);
        if (future != null) {
            future.complete(null);
        }
    }

    /**
     * Send direct message to user.
     * @param targetUsername target user username
     * @param plainText message to send
     * @throws NetworkServiceException if failed to encrypt message for user
     * @throws IOException if failed to send message
     */
    private void sendDirectMessage(String targetUsername, String plainText) throws NetworkServiceException, IOException {
        CompletableFuture<Void> future = new CompletableFuture<>();
        publicKeyFutures.put(targetUsername, future);

        client.send(new UserPublicKeyRequest(targetUsername));

        future.join();
        publicKeyFutures.remove(targetUsername);

        UserRegistry.UserPublicKeys recipientKeys = userRegistry.getKeys(targetUsername);
        if (recipientKeys == null) {
            LOGGER.error("Failed to send message to user {}", targetUsername);
            return;
        }

        byte[] data = plainText.getBytes(StandardCharsets.UTF_8);

        MessageCrypto.Sealed sealed;
        try {
            sealed = MessageCrypto.encrypt(recipientKeys.encryption(), data);
        } catch (GeneralSecurityException e) {
            throw new NetworkServiceException("Failed to encrypt message for user " + targetUsername, e);
        }

        byte[] signedPayload = MessageCrypto.signedPayload(sealed);
        byte[] signature = SigningUtils.sign(myKeys.signing().getPrivate(), signedPayload);

        EncryptedMessage message = new EncryptedMessage(
                myUsername,
                targetUsername,
                sealed.ephemeralPublicKey(),
                sealed.nonce(),
                sealed.cipherText(),
                signature,
                System.currentTimeMillis()
        );
        client.send(message);
        LOGGER.info("Message sent to {}", targetUsername);
    }

    /**
     * Handle incoming message from another user.
     * @param message incoming message
     */
    private void handleIncomingMessage(EncryptedMessage message) {
        String sender = message.sender();

        UserRegistry.UserPublicKeys senderKeys = userRegistry.getKeys(sender);
        if (senderKeys == null) {
            LOGGER.error("Failed to read message from user {}: no known public key", sender);
            return;
        }

        MessageCrypto.Sealed sealed = new MessageCrypto.Sealed(
                message.ephemeralPublicKey(), message.nonce(), message.message()
        );
        byte[] signedPayload = MessageCrypto.signedPayload(sealed);
        if (!SigningUtils.verify(senderKeys.signing(), signedPayload, message.signature())) {
            LOGGER.warn("Forged message detected from {}", sender);
            return;
        }

        try {
            byte[] data = MessageCrypto.decrypt(
                    myKeys.encryption().getPrivate(),
                    sealed
            );
            String plainText = new String(data, StandardCharsets.UTF_8);
            LOGGER.info("Message received from {}: {}", sender, plainText);
        } catch (Exception e) {
            LOGGER.error("Failed to decrypt message from {}", sender, e);
        }
    }
}
