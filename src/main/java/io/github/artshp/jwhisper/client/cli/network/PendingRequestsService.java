package io.github.artshp.jwhisper.client.cli.network;

import io.github.artshp.jwhisper.common.protocol.Identifiable;
import io.github.artshp.jwhisper.common.protocol.WhisperMessage;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service responsible for managing pending requests.
 * For example, manage registration, login, logout
 * and other requests requiring answer from server.
 */
@Slf4j
public class PendingRequestsService {

    /**
     * Pending requests map (id -> future with answer message)
     */
    private final Map<String, CompletableFuture<WhisperMessage>> pendingRequests = new ConcurrentHashMap<>();

    /**
     * Create a new instance of service.
     */
    public PendingRequestsService() {
    }

    /**
     * Put a new pending request to pending map.
     * @param key identifier of request (usually UUID), should be unique
     * @param value future to be completed with corresponding answer
     * @throws IllegalArgumentException if key already exists in the queue
     */
    public void put(String key, CompletableFuture<WhisperMessage> value) {
        pendingRequests.compute(key, (k, existingValue) -> {
            if (existingValue != null) {
                throw new IllegalArgumentException("Duplicate error! Key already exists: %s".formatted(k));
            }
            return value;
        });
    }

    /**
     * Complete pending request with provided response, delete it from pending list.
     * @param response response to pending request
     */
    public void complete(WhisperMessage response) {
        if (response instanceof Identifiable identifiable) {
            String id = identifiable.getId();
            CompletableFuture<WhisperMessage> cf = pendingRequests.remove(id);
            if (cf != null) {
                LOGGER.info("Completing pending request with id {}", id);
                cf.complete(response);
            } else {
                LOGGER.warn("Received response with id {}, but it's not in pending list", id);
            }
        }
    }
}
