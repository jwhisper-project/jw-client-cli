package io.github.artshp.jwhisper.client.cli.network;

import io.github.artshp.jwhisper.client.cli.security.MessageCrypto;
import io.github.artshp.jwhisper.client.cli.users.UserKeys;
import io.github.artshp.jwhisper.client.cli.users.UserRegistry;
import io.github.artshp.jwhisper.common.crypto.PublicKeyUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.protocol.EncryptedMessage;
import io.github.artshp.jwhisper.common.protocol.UserPublicKeyResponse;
import io.github.artshp.jwhisper.common.protocol.WhisperMessage;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.ObjectMapper;

import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.CompletionStage;

/**
 * JWhisper web socket listener. It is responsible for all incoming messages.
 */
@Slf4j
public class WebSocketListener implements WebSocket.Listener {

    /**
     * Object mapper (JSON)
     */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Service for caching information about other users.
     */
    private final UserRegistry userRegistry;

    /**
     * Pending requests service
     */
    private final PendingRequestsService pendingRequests;

    /**
     * User keys
     */
    private final UserKeys userKeys;

    /**
     * Create a new listener.
     * @param userRegistry user registry
     * @param pendingRequests pending requests service
     * @param userKeys user keys
     */
    public WebSocketListener(UserRegistry userRegistry, PendingRequestsService pendingRequests, UserKeys userKeys) {
        this.userRegistry = userRegistry;
        this.pendingRequests = pendingRequests;
        this.userKeys = userKeys;
    }

    @Override
    public void onOpen(WebSocket webSocket) {
        LOGGER.info("Connection successfully established");
        webSocket.request(1);
    }

    @Override
    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
        String incomingJson = data.toString();
        LOGGER.info("Inbound raw frame received:\n{}", incomingJson);

        WhisperMessage message = MAPPER.readValue(incomingJson, WhisperMessage.class);
        pendingRequests.complete(message);

        switch (message) {
            case UserPublicKeyResponse response -> handleKeyResponse(response);
            case EncryptedMessage encryptedMessage -> handleIncomingMessage(encryptedMessage);
            default -> {}
        }

        webSocket.request(1);
        return null;
    }

    /**
     * Handle user public keys message from relay server.
     * @param response server's message/response
     */
    private void handleKeyResponse(UserPublicKeyResponse response) {
        String targetUsername = response.targetUsername();

        if (response.found()) {
            try {
                PublicKey signing = PublicKeyUtils.newSigningPublicKey(response.publicSigningKey());
                PublicKey encryption = PublicKeyUtils.newEncryptionPublicKey(response.publicEncryptionKey());
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
                    userKeys.encryption().getPrivate(),
                    sealed
            );
            String plainText = new String(data, StandardCharsets.UTF_8);
            LOGGER.info("Message received from {}: {}", sender, plainText);
        } catch (Exception e) {
            LOGGER.error("Failed to decrypt message from {}", sender, e);
        }
    }

    @Override
    public void onError(WebSocket webSocket, Throwable error) {
        LOGGER.error("Socket network failure encountered: {}", error.getMessage());
    }

    @Override
    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
        LOGGER.info("Connection disconnected by remote server with status code {}. Reason: {}", statusCode, reason);
        return null;
    }
}
