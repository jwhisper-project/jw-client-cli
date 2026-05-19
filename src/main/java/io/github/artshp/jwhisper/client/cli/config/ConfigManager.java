package io.github.artshp.jwhisper.client.cli.config;

import io.github.artshp.jwhisper.common.exception.ConfigFileException;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Configuration manager. Responsible for creating and loading configs.
 */
@Slf4j
public class ConfigManager {

    /**
     * Default configuration file path.
     */
    private static final Path DEFAULT_CONFIG_FILE_PATH = Path.of("config.json");

    /**
     * Object mapper responsible for persisting/loading configuration.
     */
    private static final ObjectMapper MAPPER = JsonMapper.builder()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .build();

    /**
     * Configuration file path.
     */
    private final Path configPath;

    /**
     * Create a new instance of config manager with default config file path.
     */
    public ConfigManager() {
        this(DEFAULT_CONFIG_FILE_PATH);
    }

    /**
     * Create a new instance of config manager.
     * @param configPath config file path
     */
    public ConfigManager(Path configPath) {
        this.configPath = configPath;
    }

    /**
     * Persist configuration.
     * @param config config to save
     * @throws ConfigFileException if failed to save config file
     */
    public void saveConfig(ClientConfig config) throws ConfigFileException {
        LOGGER.debug("Trying to save config to {}", configPath);
        try {
            MAPPER.writeValue(configPath, config);
            LOGGER.info("Successfully saved config to {}", configPath);
        } catch (JacksonException e) {
            LOGGER.error("Failed to save config to {}", configPath, e);
            throw new ConfigFileException("Failed to save config file", e);
        }
    }

    /**
     * Load configuration.
     * @return loaded configuration
     * @throws ConfigFileException if failed to load config file
     */
    public ClientConfig loadConfig() throws ConfigFileException {
        LOGGER.debug("Trying to load config from {}", configPath);
        try {
            ClientConfig config = MAPPER.readValue(configPath, ClientConfig.class);
            LOGGER.info("Successfully loaded config from {}", configPath);

            return config;
        } catch (JacksonException e) {
            LOGGER.error("Failed to load config from {}", configPath, e);
            throw new ConfigFileException("Failed to load config file", e);
        }
    }

    /**
     * Is configuration file present?
     * @return {@code true} if config file is present, otherwise {@code false}
     */
    public boolean isConfigPresent() {
        return Files.exists(configPath);
    }
}
