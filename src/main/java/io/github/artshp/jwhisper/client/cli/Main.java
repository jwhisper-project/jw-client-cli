package io.github.artshp.jwhisper.client.cli;

import lombok.extern.slf4j.Slf4j;

/**
 * Client app entry point.
 */
@Slf4j
class Main {

    /**
     * Client app entry point.
     */
    static void main() {
        try {
            ClientApp app = new ClientApp();
            app.start();
        } catch (Exception e) {
            log.error("Unexpected error:", e);
        }
    }
}
