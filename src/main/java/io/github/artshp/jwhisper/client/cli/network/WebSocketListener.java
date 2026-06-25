package io.github.artshp.jwhisper.client.cli.network;

import io.github.artshp.jwhisper.common.protocol.WhisperMessage;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.ObjectMapper;

import java.net.http.WebSocket;
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
     * Pending requests service
     */
    private final PendingRequestsService pendingRequests;

    /**
     * Create a new listener.
     * @param pendingRequests pending requests service
     */
    public WebSocketListener(PendingRequestsService pendingRequests) {
        this.pendingRequests = pendingRequests;
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

        // TODO: finish implementation
        WhisperMessage message = MAPPER.readValue(incomingJson, WhisperMessage.class);
        pendingRequests.complete(message);

        webSocket.request(1);
        return null;
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
