package io.github.artshp.jwhisper.client.cli.users;

import java.security.KeyPair;

/**
 * User's signing and encryption keys.
 * @param signing signing key pair
 * @param encryption encryption key pair
 */
public record UserKeys(
        KeyPair signing,
        KeyPair encryption
) {
}
