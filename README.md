# Automated AST Security Reviewer & AI Remediation Engine

<p align="center">
  <img src="https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white" />
  <img src="https://img.shields.io/badge/Spring_Boot-3.3.4-6DB33F?style=for-the-badge&logo=springboot&logoColor=white" />
  <img src="https://img.shields.io/badge/Ollama-Qwen_2.5_Coder_1.5B-black?style=for-the-badge&logo=ollama&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Security-HMAC--SHA256-red?style=for-the-badge" />
</p>

An automated static analysis and AI remediation engine for GitHub pull requests. It inspects Java source code with **JavaParser** Abstract Syntax Tree (AST) visitors to detect vulnerabilities deterministically, asks a local LLM (**Qwen 2.5 Coder 1.5B via Ollama**) to suggest a fix, validates that fix, and posts it as an inline review suggestion on the PR.

No source code is sent to a third-party AI API. Only the flagged snippet goes to the local model.

---

## Architectural Flow

```text
       GitHub Pull Request Event
                  │
                  ▼  (HMAC-SHA256 Signature Checked)
┌─────────────────────────────────────────────────────────┐
│ Spring Boot Webhook Controller (/api/webhook/github)    │
│                                                         │
│ 1. Cryptographic Handshake                              │
│    └── Verifies X-Hub-Signature-256 with constant-time  │
│        MessageDigest.isEqual to prevent timing attacks  │
│                                                         │
│ 2. Deterministic AST Analysis (JavaParser)              │
│    ├── SqlInjectionVisitor (dynamic string concat)      │
│    └── HardcodedSecretVisitor (suspicious var names +   │
│        string literal initializer inspection)           │
│                                                         │
│ 3. On-Premise AI Patch Synthesis                        │
│    └── Local Ollama Client (qwen2.5-coder:1.5b)         │
│        (No source code sent to third-party AI APIs)     │
│                                                         │
│ 4. In-Memory AST Syntax Validation (FixValidator)       │
│    └── Regex code block extraction + JavaParser check   │
│        (Rejects markdown leakage and malformed syntax)  │
│                                                         │
│ 5. Automated GitHub REST Review Dispatch                │
│    └── Posts inline review suggestions on the PR diff   │
└─────────────────────────────────────────────────────────┘
```

---

## Before-and-After Remediation Example

**1. Insecure code detected in a pull request**

The AST visitor inspects variable declarations and method calls and flags dynamic string concatenation inside query execution:

```java
public User findUser(String username) {
    // Flagged by SqlInjectionVisitor
    String query = "SELECT * FROM users WHERE username = '" + username + "'";
    return entityManager.createNativeQuery(query, User.class).getSingleResult();
}
```

**2. Validated AI suggestion**

The engine prompts the local Ollama instance, strips markdown formatting, verifies the patch parses cleanly with `StaticJavaParser`, and publishes an inline GitHub suggestion:

```java
public User findUser(String username) {
    String query = "SELECT * FROM users WHERE username = :username";
    return entityManager.createNativeQuery(query, User.class)
        .setParameter("username", username)
        .getSingleResult();
}
```

---

## Key Features

- **Deterministic AST scanning:** traverses the syntax tree with JavaParser instead of regex-scanning raw file text.
- **Credential identification:** flags variables named like `password`, `secret`, `token` or `apikey` that are assigned plain string literals.
- **In-memory syntax validation:** `FixValidator` extracts generated code blocks and confirms they form valid Java syntax before anything is posted to GitHub.
- **Constant-time HMAC verification:** `HmacVerifier` validates GitHub's `X-Hub-Signature-256` header with `MessageDigest.isEqual` to avoid timing side channels.
- **No third-party AI data transfer:** talks to a local Ollama instance on port `11434`, so code stays on your own infrastructure.

---

## Project Structure

```text
ast-reviewer/
├── src/main/java/com/reviewer/
│   ├── AstSecurityReviewerApplication.java
│   ├── controller/
│   │   └── WebhookController.java       # POST /api/webhook/github handler
│   ├── engine/
│   │   └── FixValidator.java            # Code-block extraction and syntax parsing
│   ├── model/
│   │   └── Finding.java                 # Vulnerability metadata model
│   ├── security/
│   │   └── HmacVerifier.java            # Constant-time HMAC-SHA256 validator
│   ├── service/
│   │   ├── GitHubClient.java            # GitHub REST API client
│   │   ├── OllamaClient.java            # Local LLM client (qwen2.5-coder:1.5b)
│   │   └── ReviewService.java           # Review pipeline coordinator
│   └── visitors/
│       ├── HardcodedSecretVisitor.java  # Sensitive variable initializer detector
│       └── SqlInjectionVisitor.java     # Dynamic SQL concatenation detector
├── src/test/java/com/reviewer/
│   └── AstSecurityReviewerTest.java     # 37-case unit and regression suite
├── Dockerfile                           # Container definition
├── docker-compose.yml                   # Service orchestration
├── pom.xml                              # Build configuration (Java 21, Spring Boot 3.3.4)
└── README.md
```

---

## Build & Run

**Prerequisites:** JDK 21+, Apache Maven, and Ollama running locally (`ollama pull qwen2.5-coder:1.5b`).

**1. Configure properties**

```bash
export GITHUB_WEBHOOK_SECRET="your_webhook_secret"
export GITHUB_TOKEN="ghp_your_github_personal_access_token"
```

> If `github.webhook.secret` is blank, `HmacVerifier` runs in development bypass mode and skips signature checks. Never leave it blank in production.

**2. Build and run**

```bash
mvn clean package
mvn spring-boot:run   # serves on port 8080
```

**3. Or run with Docker**

```bash
docker compose up --build
```

Point your repository's webhook at `POST /api/webhook/github` with content type `application/json` and the same secret.

---

## Testing

```bash
mvn test
```

```text
Tests run: 37, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

The 37 tests cover:

- Dynamic SQL string concatenation detection and false-positive filtering
- Literal credential assignments against variable-name sets
- Code-block isolation and AST parse validation in `FixValidator`
- Valid, invalid, malformed and bypassed HMAC-SHA256 signatures

---

## Current Scope & Limitations

- **Syntax validation only:** `FixValidator` checks syntax with `StaticJavaParser.parseCompilationUnit()`. It does not do symbol resolution, type resolution or classpath compilation.
- **Two rules so far:** dynamic SQL concatenation and hardcoded string secrets. Cross-file taint tracking and broader CWE coverage are not implemented.
- **Model size:** defaults to `qwen2.5-coder:1.5b` for fast local inference. Complex refactors may need a larger model, and suggestions should be reviewed by a person.

---

## Tech Stack

- **Language & framework:** Java 21, Spring Boot 3.3.4
- **AST parsing:** JavaParser
- **Local AI:** Ollama (qwen2.5-coder:1.5b)
- **Security:** HMAC-SHA256 (`javax.crypto.Mac`, constant-time `MessageDigest.isEqual`)
- **Deployment & testing:** Docker, Docker Compose, Maven, JUnit
