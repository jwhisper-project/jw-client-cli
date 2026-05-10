package io.github.artshp.jwhisper.client.cli;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class UserRegistry {

    private final Map<String, PublicKey> signingPublicKeys = new HashMap<>();

    public synchronized void addUserPublicKeys(String username, PublicKey signingPublicKey) {
        signingPublicKeys.put(username, signingPublicKey);
    }

    public synchronized PublicKey getSigningKey(String username) {
        return signingPublicKeys.get(username);
    }
}
