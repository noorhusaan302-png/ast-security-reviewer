package com.reviewer.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

public class OllamaClient {
    private static final String OLLAMA_URL = "http://localhost:11434/api/generate";
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String modelName;

    public OllamaClient(String modelName) {
        this.modelName = modelName;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    public String getFix(String ruleName, String codeSnippet) throws Exception {
        String prompt = """
            You are an automated Java code remediation tool.
            Issue: %s
            Flawed Code:
            %s

            Instruction:
            Provide ONLY the corrected Java code snippet that fixes this issue.
            Do not include explanations. Do not include markdown code fences (like ```java). Output pure Java code only.
            """.formatted(ruleName, codeSnippet);

        Map<String, Object> requestBody = Map.of(
            "model", this.modelName,
            "prompt", prompt,
            "stream", false
        );

        String jsonPayload = objectMapper.writeValueAsString(requestBody);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(OLLAMA_URL))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Ollama API failed with status code: " + response.statusCode());
        }

        JsonNode root = objectMapper.readTree(response.body());
        return root.path("response").asText().trim();
    }
}
