package io.github.artshp.jwhisper.client.cli.network;

import io.github.artshp.jwhisper.client.cli.security.ServerTrustManager;
import io.github.artshp.jwhisper.client.cli.users.UserKeys;
import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.protocol.MessageTransport;
import io.github.artshp.jwhisper.common.protocol.RegisterRequest;
import io.github.artshp.jwhisper.common.protocol.StatusResponse;
import io.github.artshp.jwhisper.common.protocol.WhisperMessage;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Network client.
 */
@Slf4j
public class NetworkClient implements AutoCloseable {

    /**
     * Service responsible for network communication.
     */
    private final MessageTransport transport = new MessageTransport();

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
     * Client socket.
     */
    private SSLSocket socket;

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
     */
    public void connect() {
        LOGGER.info("Connecting to relay at {}:{}...", host, port);

        try {
            SSLSocketFactory factory = trustManager.getSSLSocketFactory(); /* (SSLSocketFactory) SSLSocketFactory.getDefault(); */

            socket = (SSLSocket) factory.createSocket(host, port);

            socket.setEnabledProtocols(new String[]{SecurityUtils.SSL_PROTOCOL});
            socket.startHandshake();

            LOGGER.debug("TLS connection established");
        } catch (IOException e) {
            LOGGER.error("Error connecting to relay", e);
            throw new RuntimeException(e);
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
                keys.signing().getPublic().getEncoded(),
                keys.encryption().getPublic().getEncoded(),
                signature
        );

        send(request);
        WhisperMessage response = receive();

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
     * Send message to server.
     * @param message message to send
     * @throws IOException if failed to send message
     */
    public void send(WhisperMessage message) throws IOException {
        transport.sendMessage(socket.getOutputStream(), message);
    }

    /**
     * Receive message from server.
     * @return received message
     * @throws IOException if failed to receive message
     */
    public WhisperMessage receive() throws IOException {
        return transport.receiveMessage(socket.getInputStream(), WhisperMessage.class);
    }

    /**
     * Stop client, close connection to server.
     * @throws IOException if an I/O error occurs when closing the socket
     */
    @Override
    public void close() throws IOException {
        LOGGER.info("Closing connection to relay");
        if (socket != null) {
            socket.close();
        }
    }
}
