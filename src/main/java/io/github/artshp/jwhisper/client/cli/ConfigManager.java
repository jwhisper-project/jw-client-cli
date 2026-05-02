package io.github.artshp.jwhisper.client.cli;

import io.github.artshp.jwhisper.client.cli.exception.ConfigFileException;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.nio.file.Files;
import java.nio.file.Path;

@Slf4j
public class ConfigManager {

    private static final String CONFIG_FILE = "config.json";
    private static final Path CONFIG_FILE_PATH = Path.of(CONFIG_FILE);

    private static final ObjectMapper mapper = JsonMapper.builder()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .build();

    public void saveConfig(ClientConfig config) throws ConfigFileException {
        log.debug("Trying to save config to {}", CONFIG_FILE_PATH);
        try {
            mapper.writeValue(CONFIG_FILE_PATH, config);
            log.info("Successfully saved config to {}", CONFIG_FILE_PATH);
        } catch (JacksonException e) {
            log.error("Failed to save config to {}", CONFIG_FILE_PATH, e);
            throw new ConfigFileException("Failed to save config file", e);
        }
    }

    public ClientConfig loadConfig() throws ConfigFileException {
        log.debug("Trying to load config from {}", CONFIG_FILE_PATH);
        try {
            ClientConfig config = mapper.readValue(CONFIG_FILE_PATH, ClientConfig.class);
            log.info("Successfully loaded config from {}", CONFIG_FILE_PATH);

            return config;
        } catch (JacksonException e) {
            log.error("Failed to load config from {}", CONFIG_FILE_PATH, e);
            throw new ConfigFileException("Failed to load config file", e);
        }
    }

    public boolean isConfigPresent() {
        return Files.exists(CONFIG_FILE_PATH);
    }
}
