package com.reviewer.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

@Component
public class GitHubClient {

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${github.token:}")
    private String githubToken;

    public void postPrReview(String repoFullName, int prNumber, String commitId, List<Map<String, Object>> comments) {
        if (githubToken == null || githubToken.isBlank()) {
            System.out.println("[GITHUB SKIPPED] No GITHUB_TOKEN configured. Logging comments locally.");
            return;
        }

        try {
            String url = "https://api.github.com/repos/" + repoFullName + "/pulls/" + prNumber + "/reviews";

            Map<String, Object> body = Map.of(
                "commit_id", commitId,
                "event", "COMMENT",
                "body", "🤖 **AST Security & LLM Review Summary**: Violations detected and patches generated.",
                "comments", comments
            );

            String jsonPayload = objectMapper.writeValueAsString(body);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + githubToken)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200 || response.statusCode() == 201) {
                System.out.println("[GITHUB POST SUCCESS] Review posted to PR #" + prNumber);
            } else {
                System.err.println("[GITHUB ERROR] Status: " + response.statusCode() + " Body: " + response.body());
            }

        } catch (Exception e) {
            System.err.println("Failed to post PR review to GitHub: " + e.getMessage());
        }
    }
}
