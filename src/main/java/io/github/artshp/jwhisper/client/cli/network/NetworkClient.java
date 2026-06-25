package io.github.artshp.jwhisper.client.cli.network;

import io.github.artshp.jwhisper.client.cli.security.ServerTrustManager;
import io.github.artshp.jwhisper.client.cli.users.UserKeys;
import io.github.artshp.jwhisper.common.crypto.PublicKeyUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.protocol.*;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
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
     * Trust manager needed to trust only to the white list of servers.
     */
    private final ServerTrustManager trustManager;

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
     * @param host relay's hostname
     * @param port relay's port
     */
    public NetworkClient(ServerTrustManager trustManager, String host, int port) {
        this.trustManager = trustManager;
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
                    .buildAsync(uri, new WebSocketListener(pendingRequests))
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
