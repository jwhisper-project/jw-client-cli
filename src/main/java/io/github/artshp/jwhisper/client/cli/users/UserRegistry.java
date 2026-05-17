package io.github.artshp.jwhisper.client.cli.users;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Service for caching information about other users.
 * This class is thread-safe.
 */
public class UserRegistry {

    /**
     * Users' usernames to public keys mapping (cache).
     */
    private final Map<String, UserPublicKeys> keys = new HashMap<>();

    /**
     * Create a new user registry.
     */
    public UserRegistry() {
    }

    /**
     * Put user's public keys to cache. If already exist, then rewrite.
     * <p>
     * This method is thread-safe.
     * @param username user's username
     * @param signing user's signing public key
     * @param encryption user's encryption public key
     */
    public synchronized void addUserPublicKeys(String username, PublicKey signing, PublicKey encryption) {
        keys.put(username, new UserPublicKeys(signing, encryption));
    }

    /**
     * Mark user's public keys unavailable.
     * <p>
     * This method is thread-safe.
     * @param username user's username
     */
    public synchronized void markUnavailable(String username) {
        keys.put(username, null);
    }

    /**
     * Get public keys of user
     * @param username user's username
     * @return public keys of user if present cache, otherwise {@code null}
     */
    public synchronized UserPublicKeys getKeys(String username) {
        return keys.get(username);
    }

    /**
     * User's public signing and encryption keys bundle.
     * @param signing user's public signing key
     * @param encryption user's public encryption key
     */
    public record UserPublicKeys(
            PublicKey signing,
            PublicKey encryption
    ) {
    }
}
