package io.github.artshp.jwhisper.client.cli.network;

import io.github.artshp.jwhisper.client.cli.security.MessageCrypto;
import io.github.artshp.jwhisper.client.cli.users.UserKeys;
import io.github.artshp.jwhisper.client.cli.users.UserRegistry;
import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.io.ConsoleUtils;
import io.github.artshp.jwhisper.common.protocol.*;
import lombok.extern.slf4j.Slf4j;

import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.concurrent.*;

@Slf4j
public class CommunicationManager {

    private final String myUsername;
    private final UserKeys myKeys;
    private final NetworkClient client;
    private final UserRegistry userRegistry = new UserRegistry();
    private final CompletableFuture<StatusResponse> unregisterFuture = new CompletableFuture<>();
    private final Thread listenThread = Thread.ofVirtual()
            .name("listener")
            .unstarted(this::listenLoop);
    private final Map<String, CompletableFuture<Void>> publicKeyFutures = new ConcurrentHashMap<>();
    private volatile boolean shuttingDown = false;

    public CommunicationManager(String myUsername, UserKeys myKeys, NetworkClient client) {
        this.myUsername = myUsername;
        this.myKeys = myKeys;
        this.client = client;
    }

    public void start() {
        listenThread.start();
        uiLoop();
    }

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

    private void uiLoop() {
        LOGGER.info("Starting chat.");
        while (true) {
            try {
                String cmd = ConsoleUtils.readString("", _ -> true, null, 1);
                if (cmd.startsWith("/msg")) {
                    // Example: /msg bob Hello!
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

    private void sendDirectMessage(String targetUsername, String plainText) throws Exception {
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

        MessageCrypto.Sealed sealed = MessageCrypto.encrypt(recipientKeys.encryption(), data);
        byte[] signedPayload = MessageCrypto.signedPayload(
                sealed.ephemeralPublicKey(), sealed.nonce(), sealed.cipherText()
        );
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

    private void handleIncomingMessage(EncryptedMessage message) {
        String sender = message.sender();

        UserRegistry.UserPublicKeys senderKeys = userRegistry.getKeys(sender);
        if (senderKeys == null) {
            LOGGER.error("Failed to read message from user {}: no known public key", sender);
            return;
        }

        byte[] signedPayload = MessageCrypto.signedPayload(
                message.ephemeralPublicKey(), message.nonce(), message.message()
        );
        if (!SigningUtils.verify(senderKeys.signing(), signedPayload, message.signature())) {
            LOGGER.warn("Forged message detected from {}", sender);
            return;
        }

        try {
            byte[] data = MessageCrypto.decrypt(
                    myKeys.encryption().getPrivate(),
                    message.ephemeralPublicKey(),
                    message.nonce(),
                    message.message()
            );
            String plainText = new String(data, StandardCharsets.UTF_8);
            LOGGER.info("Message received from {}: {}", sender, plainText);
        } catch (Exception e) {
            LOGGER.error("Failed to decrypt message from {}", sender, e);
        }
    }
}
