package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.common.crypto.SecurityUtils;
import io.github.artshp.jwhisper.common.crypto.SigningUtils;
import io.github.artshp.jwhisper.common.protocol.*;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.security.KeyPair;

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
        log.info("Connecting to relay at {}:{}...", host, port);

        try {
            SSLSocketFactory factory = trustManager.getSSLSocketFactory(); /* (SSLSocketFactory) SSLSocketFactory.getDefault(); */

            socket = (SSLSocket) factory.createSocket(host, port);

            socket.setEnabledProtocols(new String[]{SecurityUtils.SSL_PROTOCOL});
            socket.startHandshake();

            log.debug("TLS connection established");
        } catch (IOException e) {
            log.error("Error connecting to relay", e);
            throw new RuntimeException(e);
        }
    }

    public boolean register(String username, KeyPair keyPair) throws IOException {
        byte[] signature = SigningUtils.sign(keyPair.getPrivate(), username.getBytes());
        RegisterRequest request = new RegisterRequest(
                username,
                keyPair.getPublic().getEncoded(),
                signature
        );

        send(request);
        WhisperMessage response = receive();

        if (response instanceof StatusResponse statusResponse) {
            if (statusResponse.success()) {
                log.info("Successfully registered user {}", username);
                return true;
            } else {
                log.error("Failed to register user {}", username);
            }
        } else {
            log.error("Unexpected response {}. Failed to register user {}", response, username);
        }

        return false;
    }

    public boolean unregister(String username) throws IOException {
        UnregisterRequest request = new UnregisterRequest();

        send(request);
        WhisperMessage response = receive();

        if (response instanceof StatusResponse statusResponse) {
            if (statusResponse.success()) {
                log.info("Successfully unregistered user {}", username);
                return true;
            } else {
                log.error("Failed to unregister user {}", username);
            }
        } else {
            log.error("Unexpected response {}. Failed to unregister user {}", response, username);
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
        log.info("Closing connection to relay");
        if (socket != null) {
            socket.close();
        }
    }
}
