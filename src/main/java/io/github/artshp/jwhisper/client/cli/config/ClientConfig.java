package io.github.artshp.jwhisper.client.cli.config;

import tools.jackson.databind.ObjectMapper;

/**
 * Class representing client configuration.
 * @param hostname relay's hostname
 * @param port relay's port
 */
public record ClientConfig(String hostname, int port) {

    private static final ObjectMapper mapper = new ObjectMapper();

    public String toPrettyString() {
        return mapper.writeValueAsString(this);
    }
}
