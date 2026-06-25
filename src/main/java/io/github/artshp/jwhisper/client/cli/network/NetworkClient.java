package io.github.artshp.jwhisper.client.cli.network;

import io.github.artshp.jwhisper.client.cli.security.MessageCrypto;
import io.github.artshp.jwhisper.client.cli.security.ServerTrustManager;
import io.github.artshp.jwhisper.client.cli.users.UserKeys;
import io.github.artshp.jwhisper.client.cli.users.UserRegistry;
import io.github.artshp.jwhisper.common.crypto.PublicKeyUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.exception.NetworkServiceException;
import io.github.artshp.jwhisper.common.protocol.*;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Network client.
 */
@Slf4j
public class NetworkClient implements AutoCloseable {

    /**
     * Web Socket Secure protocol (scheme).
     */
    private static final String WEBSOCKET_PROTOCOL = "wss";

    /**
     * Endpoint responsible for JWhisper messages.
     */
    private static final String WEBSOCKET_ENDPOINT = "/whisper";

    /**
     * Object mapper for JSON.
     */
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Service for pending requests.
     */
    private final PendingRequestsService pendingRequests = new PendingRequestsService();

    /**
     * Service for caching information about other users.
     */
    private final UserRegistry userRegistry = new UserRegistry();

    /**
     * Trust manager needed to trust only to the white list of servers.
     */
    private final ServerTrustManager trustManager;

    /**
     * User keys.
     */
    private final UserKeys userKeys;

    /**
     * Relay's hostname.
     */
    private final String host;

    /**
     * Relay's port.
     */
    private final int port;

    /**
     * Client web socket.
     */
    private WebSocket webSocket;

    /**
     * Create a new network client.
     * @param trustManager server trust manager
     * @param userKeys user keys
     * @param host relay's hostname
     * @param port relay's port
     */
    public NetworkClient(ServerTrustManager trustManager, UserKeys userKeys, String host, int port) {
        this.trustManager = trustManager;
        this.userKeys = userKeys;
        this.host = host;
        this.port = port;
    }

    /**
     * Connect to relay server.
     * @return completed future if connected successfully, otherwise one completed exceptionally
     */
    public CompletableFuture<Void> connect() {
        LOGGER.info("Connecting to relay at {}:{}...", host, port);

        try {
            HttpClient client = trustManager.getHttpClient();
            URI uri = new URI(WEBSOCKET_PROTOCOL, null, host, port, WEBSOCKET_ENDPOINT, null, null);

            return client.newWebSocketBuilder()
                    .buildAsync(uri, new WebSocketListener(userRegistry, pendingRequests, userKeys))
                    .thenAccept(ws -> webSocket = ws);

        } catch (Exception e) {
            LOGGER.error("Error connecting to relay", e);
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Register user on the server.
     * @param username user's username
     * @param keys user's signing and encryption keys for network communication
     * @return {@code true} if user was registered successfully, otherwise {@code false}
     * @throws IOException if failed to send request or failed to receive response.
     */
    public boolean register(String username, UserKeys keys) throws IOException {
        byte[] signature = SigningUtils.sign(
                keys.signing().getPrivate(),
                username.getBytes(StandardCharsets.UTF_8)
        );
        RegisterRequest request = new RegisterRequest(
                username,
                PublicKeyUtils.toRawBytes(keys.signing().getPublic()),
                PublicKeyUtils.toRawBytes(keys.encryption().getPublic()),
                signature
        );

        CompletableFuture<WhisperMessage> cf = send(request);
        WhisperMessage response = cf.join();

        if (response instanceof StatusResponse statusResponse) {
            if (statusResponse.success()) {
                LOGGER.info("Successfully registered user {}", username);
                return true;
            } else {
                LOGGER.error("Failed to register user {}", username);
            }
        } else {
            LOGGER.error("Unexpected response {}. Failed to register user {}", response, username);
        }

        return false;
    }

    /**
     * Log in user on the server.
     * @param username user's username
     * @param privateSigningKey private signing key used for generating ownership signature
     * @return {@code true} if user was logged-in successfully, otherwise {@code false}
     * @throws IOException if failed to send request or failed to receive response.
     */
    public boolean login(String username, PrivateKey privateSigningKey) throws IOException {
        byte[] signature = SigningUtils.sign(
                privateSigningKey,
                username.getBytes(StandardCharsets.UTF_8)
        );
        LoginRequest request = new LoginRequest(
                username,
                signature
        );

        CompletableFuture<WhisperMessage> cf = send(request);
        WhisperMessage response = cf.join();

        if (response instanceof StatusResponse statusResponse) {
            if (statusResponse.success()) {
                LOGGER.info("Successfully logged in user {}", username);
                return true;
            } else {
                LOGGER.error("Failed to log in user {}", username);
            }
        } else {
            LOGGER.error("Unexpected response {}. Failed to log in user {}", response, username);
        }

        return false;
    }

    /**
     * Log out user on the server.
     * @return {@code true} if user was logged-out successfully, otherwise {@code false}
     * @throws IOException if failed to send request or failed to receive response.
     */
    public boolean logout() throws IOException {
        LogoutRequest request = new LogoutRequest();

        CompletableFuture<WhisperMessage> cf = send(request);
        WhisperMessage response = cf.join();

        if (response instanceof StatusResponse statusResponse) {
            if (statusResponse.success()) {
                LOGGER.info("Successfully logged out user");
                return true;
            } else {
                LOGGER.error("Failed to log out user");
            }
        } else {
            LOGGER.error("Unexpected response {}. Failed to log out user", response);
        }

        return false;
    }

    /**
     * Request public keys of the user.
     * @param targetUsername target user's username
     * @return user public keys if found, otherwise {@link Optional#empty()}
     * @throws IOException if failed to send request or failed to receive response.
     */
    public Optional<UserRegistry.UserPublicKeys> requestUserPublicKeys(String targetUsername) throws IOException {
        UserPublicKeyRequest request = new UserPublicKeyRequest(targetUsername);

        CompletableFuture<WhisperMessage> cf = send(request);
        WhisperMessage response = cf.join();

        if (response instanceof UserPublicKeyResponse publicKeyResponse) {
            if (publicKeyResponse.found()) {
                LOGGER.info("Successfully found public keys of user {}", targetUsername);
                return parseUserPublicKeysResponse(publicKeyResponse);
            } else {
                LOGGER.error("Failed to find public keys of user {}", targetUsername);
            }
        } else {
            LOGGER.error("Unexpected response {}. Failed to find public keys of user {}", response, targetUsername);
        }

        return Optional.empty();
    }

    /**
     * Send direct message to user.
     * @param username user username
     * @param privateSigningKey private signing key of user
     * @param targetUsername target user username
     * @param plainText message to send
     * @throws NetworkServiceException if failed to encrypt message for user
     * @throws IOException if failed to send message
     */
    public boolean sendDirectMessage(String username, PrivateKey privateSigningKey, String targetUsername, String plainText) throws NetworkServiceException, IOException {
        UserRegistry.UserPublicKeys recipientKeys = userRegistry.getKeys(targetUsername);
        if (recipientKeys == null) {
            LOGGER.warn("User {} is unknown, i.e. no public keys found", targetUsername);
            LOGGER.info("Requesting public keys of user {}", targetUsername);

            Optional<UserRegistry.UserPublicKeys> optionalPublicKeys = requestUserPublicKeys(targetUsername);
            if (optionalPublicKeys.isPresent()) {
                UserRegistry.UserPublicKeys publicKeys = optionalPublicKeys.get();
                LOGGER.info("Successfully obtained public keys of user {}", targetUsername);

                // TODO: ask user if we trust this user (i.e. show fingerprints)
                userRegistry.addUserPublicKeys(targetUsername, publicKeys.signing(), publicKeys.encryption());
                recipientKeys = publicKeys;
            } else {
                LOGGER.error("Failed to get public keys of user {}", targetUsername);

                userRegistry.markUnavailable(targetUsername);
                return false;
            }
        }

        byte[] data = plainText.getBytes(StandardCharsets.UTF_8);

        MessageCrypto.Sealed sealed;
        try {
            sealed = MessageCrypto.encrypt(recipientKeys.encryption(), data);
        } catch (GeneralSecurityException e) {
            throw new NetworkServiceException("Failed to encrypt message for user " + targetUsername, e);
        }

        byte[] signedPayload = MessageCrypto.signedPayload(sealed);
        byte[] signature = SigningUtils.sign(privateSigningKey, signedPayload);

        EncryptedMessage message = new EncryptedMessage(
                username,
                targetUsername,
                sealed.ephemeralPublicKey(),
                sealed.nonce(),
                sealed.cipherText(),
                signature,
                System.currentTimeMillis()
        );

        send(message);
        LOGGER.info("Message sent to {}", targetUsername);

        return true;
    }

    /**
     * Parse user public keys from corresponding response from server.
     * @param response response from server
     * @return parsed user public keys, otherwise {@link Optional#empty()} if failed
     */
    private Optional<UserRegistry.UserPublicKeys> parseUserPublicKeysResponse(UserPublicKeyResponse response) {
        try {
            PublicKey signingPublicKey = PublicKeyUtils.newSigningPublicKey(response.publicSigningKey());
            PublicKey encryptionPublicKey = PublicKeyUtils.newEncryptionPublicKey(response.publicEncryptionKey());

            return Optional.of(
                    new UserRegistry.UserPublicKeys(signingPublicKey, encryptionPublicKey)
            );
        } catch (InvalidKeySpecException e) {
            LOGGER.error("Failed to recreate user public keys from response", e);
            return Optional.empty();
        }
    }

    /**
     * Send message to server.
     * @param message message to send
     * @throws IOException if failed to send message
     */
    public CompletableFuture<WhisperMessage> send(WhisperMessage message) throws IOException {
        String data = mapper.writeValueAsString(message);

        CompletableFuture<WhisperMessage> future = null;
        if (message instanceof Identifiable identifiable) {
            String id = identifiable.getId();
            future = new CompletableFuture<>();
            pendingRequests.put(id, future);
        }

        webSocket.sendText(data, true);

        return future;
    }

    /**
     * Receive message from server.
     * @return received message
     * @throws IOException if failed to receive message
     */
    @Deprecated
    public WhisperMessage receive() throws IOException {
        // return transport.receiveMessage(socket.getInputStream(), WhisperMessage.class);
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Stop client, close connection to server.
     * @throws IOException if an I/O error occurs when closing the web socket
     */
    @Override
    public void close() throws IOException {
        LOGGER.info("Closing connection to relay");
        if (webSocket != null) {
            webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "Closing connection").join();
        }
    }
}
