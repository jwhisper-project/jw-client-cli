package io.github.artshp.jwhisper.client.cli.config;

import tools.jackson.databind.ObjectMapper;

/**
 * Class representing client configuration.
 * @param hostname relay's hostname
 * @param port relay's port
 */
public record ClientConfig(String hostname, int port) {

    /**
     * Object mapper for pretty-printing config files.
     */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Create pretty-printed client config.
     * @return string of pretty-printed client config
     */
    public String toPrettyString() {
        return MAPPER.writeValueAsString(this);
    }
}
