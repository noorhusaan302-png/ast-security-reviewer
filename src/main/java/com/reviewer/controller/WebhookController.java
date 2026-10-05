package com.reviewer.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.reviewer.security.HmacVerifier;
import com.reviewer.service.GitHubClient;
import com.reviewer.service.ReviewService;
import com.reviewer.service.ReviewService.ReviewResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/webhook")
public class WebhookController {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ReviewService reviewService;
    private final GitHubClient gitHubClient;
    private final HmacVerifier hmacVerifier;

    public WebhookController(ReviewService reviewService, GitHubClient gitHubClient, HmacVerifier hmacVerifier) {
        this.reviewService = reviewService;
        this.gitHubClient = gitHubClient;
        this.hmacVerifier = hmacVerifier;
    }

    @PostMapping("/github")
    public ResponseEntity<Map<String, Object>> handleGithubWebhook(
            @RequestHeader(value = "X-GitHub-Event", defaultValue = "ping") String eventType,
            @RequestHeader(value = "X-Hub-Signature-256", required = false) String signatureHeader,
            @RequestBody String rawPayload) {

        // Validate cryptographic signature
        if (!hmacVerifier.isValidSignature(rawPayload, signatureHeader)) {
            System.err.println("[SECURITY ALERT] Invalid HMAC-SHA256 signature rejected.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid webhook signature"));
        }

        System.out.println("\n[WEBHOOK RECEIVED - AUTHENTICATED] Event: " + eventType);

        if ("ping".equals(eventType)) {
            return ResponseEntity.ok(Map.of("status", "pong"));
        }

        try {
            JsonNode payload = objectMapper.readTree(rawPayload);

            String action = payload.path("action").asText("unknown");
            int prNumber = payload.path("number").asInt(0);
            String repoName = payload.path("repository").path("full_name").asText("unknown");
            String commitId = payload.path("pull_request").path("head").path("sha").asText("dummy-sha");
            String path = payload.path("path").asText("VulnerableApp.java");
            String code = payload.path("source_code").asText("");

            System.out.printf("PR #%d on repo '%s' (action: %s)\n", prNumber, repoName, action);

            List<Map<String, Object>> ghComments = new ArrayList<>();
            List<Map<String, Object>> reviews = new ArrayList<>();

            if (!code.isBlank()) {
                List<ReviewResult> results = reviewService.reviewSourceCode(code);
                for (ReviewResult r : results) {
                    reviews.add(Map.of(
                        "rule", r.finding().ruleName(),
                        "severity", r.finding().severity(),
                        "line", r.finding().lineNumber(),
                        "message", r.finding().message(),
                        "flaggedCode", r.finding().codeSnippet(),
                        "suggestedFix", r.suggestedFix(),
                        "fixValidated", r.isValid()
                    ));

                    String commentBody = String.format(
                        "### ⚠️ AST Security Violation: `%s` [%s]\n\n" +
                        "**Issue:** %s\n\n" +
                        "**Proposed AST-Validated Fix:**\n```java\n%s\n```",
                        r.finding().ruleName(),
                        r.finding().severity(),
                        r.finding().message(),
                        r.suggestedFix()
                    );

                    ghComments.add(Map.of(
                        "path", path,
                        "line", r.finding().lineNumber(),
                        "side", "RIGHT",
                        "body", commentBody
                    ));
                }

                if (prNumber > 0 && !repoName.equals("unknown")) {
                    gitHubClient.postPrReview(repoName, prNumber, commitId, ghComments);
                }
            }

            return ResponseEntity.ok(Map.of(
                "status", "analyzed",
                "pr", prNumber,
                "repo", repoName,
                "findingsCount", reviews.size(),
                "reviews", reviews
            ));

        } catch (Exception e) {
            System.err.println("Webhook processing failed: " + e.getMessage());
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }
}
