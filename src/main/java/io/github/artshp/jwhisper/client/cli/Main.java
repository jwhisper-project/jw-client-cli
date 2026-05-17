package io.github.artshp.jwhisper.client.cli;

import lombok.extern.slf4j.Slf4j;

/**
 * Client app entry point.
 */
@Slf4j
final class Main {

    private Main() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Client app entry point.
     */
    static void main() {
        try {
            ClientApp app = new ClientApp();
            app.start();
        } catch (Exception e) {
            LOGGER.error("Unexpected error:", e);
        }
    }
}
