package io.github.artshp.jwhisper.client.cli;

import java.security.KeyPair;

public record UserKeys(KeyPair signing, KeyPair encryption) {
}
