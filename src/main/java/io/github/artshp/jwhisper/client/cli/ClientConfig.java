package io.github.artshp.jwhisper.client.cli;

/**
 * Class representing client configuration.
 * @param hostname relay's hostname
 * @param port relay's port
 */
public record ClientConfig(String hostname, int port) {
}
