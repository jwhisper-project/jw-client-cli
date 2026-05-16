package io.github.artshp.jwhisper.client.cli.users;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class UserRegistry {

    private final Map<String, UserPublicKeys> keys = new HashMap<>();

    public synchronized void addUserPublicKeys(String username, PublicKey signing, PublicKey encryption) {
        keys.put(username, new UserPublicKeys(signing, encryption));
    }

    public synchronized void markUnavailable(String username) {
        keys.put(username, null);
    }

    public synchronized UserPublicKeys getKeys(String username) {
        return keys.get(username);
    }

    public record UserPublicKeys(PublicKey signing, PublicKey encryption) {
    }
}
