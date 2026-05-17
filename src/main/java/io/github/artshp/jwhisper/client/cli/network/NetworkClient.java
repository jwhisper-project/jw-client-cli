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

@Slf4j
public class NetworkClient implements AutoCloseable {

    private final MessageTransport transport = new MessageTransport();
    private final ServerTrustManager trustManager;
    private final String host;
    private final int port;

    private SSLSocket socket;

    public NetworkClient(ServerTrustManager trustManager, String host, int port) {
        this.trustManager = trustManager;
        this.host = host;
        this.port = port;
    }

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

    public void send(WhisperMessage message) throws IOException {
        transport.sendMessage(socket.getOutputStream(), message);
    }

    public WhisperMessage receive() throws IOException {
        return transport.receiveMessage(socket.getInputStream(), WhisperMessage.class);
    }

    @Override
    public void close() throws IOException {
        LOGGER.info("Closing connection to relay");
        if (socket != null) {
            socket.close();
        }
    }
}
