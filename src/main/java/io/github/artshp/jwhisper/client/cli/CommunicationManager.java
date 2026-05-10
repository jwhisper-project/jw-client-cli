package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.io.ConsoleUtils;
import io.github.artshp.jwhisper.common.protocol.EncryptedMessage;
import io.github.artshp.jwhisper.common.protocol.UserPublicKeyRequest;
import io.github.artshp.jwhisper.common.protocol.UserPublicKeyResponse;
import io.github.artshp.jwhisper.common.protocol.WhisperMessage;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.CompletableFuture;

@Slf4j
public class CommunicationManager {

    private final String myUsername;
    private final PrivateKey myPrivateKey;
    private final NetworkClient client;
    private final Thread listenThread = Thread.ofVirtual()
            .name("listener")
            .unstarted(this::listenLoop);

    private PublicKey publicKey = null;
    private CompletableFuture<PublicKey> publicKeyFuture = new CompletableFuture<>();

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
                    case EncryptedMessage message -> handleIncomingMessage(message, publicKey);
                    case UserPublicKeyResponse publicKeyResponse -> handleKeyResponse(publicKeyResponse);
                    default -> log.warn("Unknown message received: {}", incoming);
                }
            }
        } catch (Exception e) {
            log.error("Connection lost.", e);
        }
    }

    private void uiLoop() {
        while (true) {
            try {
                String cmd = ConsoleUtils.readString("Enter command: ", _ -> true, null, 1);
                if (cmd.startsWith("/msg")) {
                    // Example: /msg bob Hello!
                    String[] parts = cmd.split(" ", 3);
                    sendDirectMessage(parts[1], parts[2]);
                } else if (cmd.startsWith("/exit")) {
                    log.info("Exiting.");
                    listenThread.interrupt();
                    return;
                }
            } catch (Exception e) {
                log.error("Command failed.", e);
            }
        }
    }

    private void handleKeyResponse(UserPublicKeyResponse response) {
        String targetUsername = response.targetUsername();

        if (response.found()) {
            log.info("Successfully obtained public key of user {}", targetUsername);
            try {
                publicKeyFuture.complete(SecurityUtils.newPublicKey(response.targetPublicKey()));
            } catch (InvalidKeySpecException e) {
                publicKeyFuture.complete(null);
                log.error("Failed to obtain public key of user {}", targetUsername, e);
            }
        } else {
            publicKeyFuture.complete(null);
            log.error("Failed to obtain public key of user {}", targetUsername);
        }
    }

    private void sendDirectMessage(String targetUsername, String plainText) throws Exception {
        publicKeyFuture = new CompletableFuture<>();
        client.send(new UserPublicKeyRequest(targetUsername));
        PublicKey recipientPublicKey = publicKeyFuture.get();

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

    private void handleIncomingMessage(EncryptedMessage message, PublicKey senderPublicKey) {
        // TODO: verify
        /*if (!SigningUtils.verify(senderPublicKey, message.message(), message.signature())) {
            log.warn("Forged message detected from {}", message.sender());
            return;
        }*/

        byte[] encryptedData = message.message();

        // TODO: decrypt
        byte[] data = encryptedData; // EncryptionUtils.decrypt(myPrivateKey, encryptedData);
        String plainText = new String(data, StandardCharsets.UTF_8);

        log.info("Message received from {}: {}", message.sender(), plainText);
    }
}
