package io.github.artshp.jwhisper.client.cli;

import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;

@Slf4j
public class NetworkClient implements AutoCloseable {

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

            socket.setEnabledProtocols(new String[]{"TLSv1.3"});
            socket.startHandshake();

            log.debug("TLS connection established");
        } catch (IOException e) {
            log.error("Error connecting to relay", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void close() throws IOException {
        log.info("Closing connection to relay");
        if (socket != null) {
            socket.close();
        }
    }
}
