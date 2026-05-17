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
     * Configuration file name.
     */
    private static final String CONFIG_FILE = "config.json";

    /**
     * Configuration file path.
     */
    private static final Path CONFIG_FILE_PATH = Path.of(CONFIG_FILE);

    /**
     * Object mapper responsible for persisting/loading configuration.
     */
    private static final ObjectMapper MAPPER = JsonMapper.builder()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .build();

    /**
     * Create a new instance of config manager.
     */
    public ConfigManager() {
    }

    /**
     * Persist configuration.
     * @param config config to save
     * @throws ConfigFileException if failed to save config file
     */
    public void saveConfig(ClientConfig config) throws ConfigFileException {
        LOGGER.debug("Trying to save config to {}", CONFIG_FILE_PATH);
        try {
            MAPPER.writeValue(CONFIG_FILE_PATH, config);
            LOGGER.info("Successfully saved config to {}", CONFIG_FILE_PATH);
        } catch (JacksonException e) {
            LOGGER.error("Failed to save config to {}", CONFIG_FILE_PATH, e);
            throw new ConfigFileException("Failed to save config file", e);
        }
    }

    /**
     * Load configuration.
     * @return loaded configuration
     * @throws ConfigFileException if failed to load config file
     */
    public ClientConfig loadConfig() throws ConfigFileException {
        LOGGER.debug("Trying to load config from {}", CONFIG_FILE_PATH);
        try {
            ClientConfig config = MAPPER.readValue(CONFIG_FILE_PATH, ClientConfig.class);
            LOGGER.info("Successfully loaded config from {}", CONFIG_FILE_PATH);

            return config;
        } catch (JacksonException e) {
            LOGGER.error("Failed to load config from {}", CONFIG_FILE_PATH, e);
            throw new ConfigFileException("Failed to load config file", e);
        }
    }

    /**
     * Is configuration file present?
     * @return {@code true} if config file is present, otherwise {@code false}
     */
    public boolean isConfigPresent() {
        return Files.exists(CONFIG_FILE_PATH);
    }
}
