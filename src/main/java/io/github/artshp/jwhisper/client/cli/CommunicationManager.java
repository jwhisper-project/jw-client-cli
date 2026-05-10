package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.io.ConsoleUtils;
import io.github.artshp.jwhisper.common.protocol.*;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.concurrent.*;

@Slf4j
public class CommunicationManager {

    private final String myUsername;
    private final PrivateKey myPrivateKey;
    private final NetworkClient client;
    private final UserRegistry userRegistry = new UserRegistry();
    private final CompletableFuture<StatusResponse> unregisterFuture = new CompletableFuture<>();
    private final Thread listenThread = Thread.ofVirtual()
            .name("listener")
            .unstarted(this::listenLoop);
    private final Map<String, CompletableFuture<Void>> publicKeyFutures = new ConcurrentHashMap<>();

    public CommunicationManager(String myUsername, PrivateKey myPrivateKey, NetworkClient client) {
        this.myUsername = myUsername;
        this.myPrivateKey = myPrivateKey;
        this.client = client;
    }

    public void start() {
        listenThread.start();
        uiLoop();
    }

    private void listenLoop() {
        try {
            while (true) {
                WhisperMessage incoming = client.receive();

                switch (incoming) {
                    case EncryptedMessage message -> handleIncomingMessage(message);
                    case UserPublicKeyResponse publicKeyResponse -> handleKeyResponse(publicKeyResponse);
                    case StatusResponse statusResponse -> unregisterFuture.complete(statusResponse);
                    default -> log.warn("Unknown message received: {}", incoming);
                }
            }
        } catch (Exception e) {
            log.error("Connection lost.", e);
        }
    }

    private void uiLoop() {
        log.info("Starting chat.");
        while (true) {
            try {
                String cmd = ConsoleUtils.readString("", _ -> true, null, 1);
                if (cmd.startsWith("/msg")) {
                    // Example: /msg bob Hello!
                    String[] parts = cmd.split(" ", 3);
                    sendDirectMessage(parts[1], parts[2]);
                } else if (cmd.startsWith("/exit")) {
                    log.info("Exiting.");
                    unregister();
                    return;
                }
            } catch (Exception e) {
                log.error("Command failed.", e);
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
            log.error("Unregistering failed.", e);
            return;
        }

        if (response.success()) {
            log.info("Successfully unregistered user {}", myUsername);
        } else {
            log.error("Failed to unregister user {}", myUsername);
        }
    }

    private void handleKeyResponse(UserPublicKeyResponse response) {
        String targetUsername = response.targetUsername();

        if (response.found()) {
            log.info("Successfully obtained public key of user {}", targetUsername);
            try {
                PublicKey publicKey = SecurityUtils.newPublicKey(response.targetPublicKey());
                userRegistry.addUserPublicKeys(targetUsername, publicKey);

            } catch (InvalidKeySpecException e) {
                log.error("Failed to obtain public key of user {}", targetUsername, e);
                userRegistry.addUserPublicKeys(targetUsername, null);
            }
        } else {
            log.error("Failed to obtain public key of user {}", targetUsername);
            userRegistry.addUserPublicKeys(targetUsername, null);
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

        PublicKey recipientPublicKey = userRegistry.getSigningKey(targetUsername);
        if (recipientPublicKey == null) {
            log.error("Failed to send message to user {}", targetUsername);
            return;
        }

        byte[] data = plainText.getBytes(StandardCharsets.UTF_8);

        // TODO: encrypt
        byte[] encryptedData = data; // EncryptionUtils.encrypt(recipientPublicKey, data);
        EncryptedMessage message = new EncryptedMessage(
                myUsername,
                targetUsername,
                encryptedData,
                SigningUtils.sign(myPrivateKey, encryptedData),
                System.currentTimeMillis()
        );
        client.send(message);
        log.info("Message sent to {}", targetUsername);
    }

    private void handleIncomingMessage(EncryptedMessage message) {
        String sender = message.sender();

        PublicKey senderPublicKey = userRegistry.getSigningKey(sender);
        if (senderPublicKey == null) {
            log.error("Failed to read message from user {}", sender);
            return;
        }

        if (!SigningUtils.verify(senderPublicKey, message.message(), message.signature())) {
            log.warn("Forged message detected from {}", sender);
            return;
        }

        byte[] encryptedData = message.message();

        // TODO: decrypt
        byte[] data = encryptedData; // EncryptionUtils.decrypt(myPrivateKey, encryptedData);
        String plainText = new String(data, StandardCharsets.UTF_8);

        log.info("Message received from {}: {}", message.sender(), plainText);
    }
}
