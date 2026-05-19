package io.github.artshp.jwhisper.client.cli.config;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link ConfigManager} class.
 */
class ConfigManagerTest {

    @TempDir
    private static Path TEMP_FOLDER;

    @Tag("unit")
    @Test
    void testSuccessfulSaveLoadConfig() {
        Path filePath = TEMP_FOLDER.resolve("config.json");
        ConfigManager configManager = new ConfigManager(filePath);
        ClientConfig config = new ClientConfig("localhost", 8080);

        configManager.saveConfig(config);
        ClientConfig readConfig = configManager.loadConfig();

        assertTrue(Files.exists(filePath));
        assertEquals(config, readConfig);
    }
}
