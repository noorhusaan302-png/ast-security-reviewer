# Automated AST Security Reviewer & AI Remediation Engine

<p align="center">
  <img src="https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white" />
  <img src="https://img.shields.io/badge/Spring_Boot-3.3.4-6DB33F?style=for-the-badge&logo=springboot&logoColor=white" />
  <img src="https://img.shields.io/badge/Ollama-Qwen_2.5_Coder_1.5B-black?style=for-the-badge&logo=ollama&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Security-HMAC--SHA256-red?style=for-the-badge" />
</p>

## Try it in 2 minutes

Scan any Java repo on GitHub for SQL injection and hardcoded secrets. No install, no AI model, free.

1. In your repo, create a file at `.github/workflows/security-scan.yml`
2. Paste this in and commit:

   ```yaml
   name: Security scan
   on: [push, pull_request]
   jobs:
     scan:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v5
         - uses: noorhusaan302-png/ast-security-reviewer@v1.1.0
   ```

3. Open the **Actions** tab. Any finding shows the file, the line and the problem, and it's marked right on your pull request.

Found something wrong, or a false alarm? [Open an issue](https://github.com/noorhusaan302-png/ast-security-reviewer/issues). Feedback helps a lot.

---

An automated static analysis and AI remediation engine for GitHub pull requests. It inspects Java source code with **JavaParser** Abstract Syntax Tree (AST) visitors to detect vulnerabilities deterministically, asks a local LLM (**Qwen 2.5 Coder 1.5B via Ollama**) to suggest a fix, validates that fix, and posts it as an inline review suggestion on the PR.

No source code is sent to a third-party AI API. Only the flagged snippet goes to the local model.

---

## Use It as a GitHub Action

Add the scanner to any Java repository. It runs on every pull request, needs no AI model, and marks each finding on the exact line in the PR.

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: noorhusaan302-png/ast-security-reviewer@v1.1.0
```

| Input | Default | Meaning |
| :--- | :--- | :--- |
| `path` | `.` | File or folder to scan |
| `fail-on-findings` | `true` | Fail the job when something is found |
| `include-tests` | `false` | Also scan test folders (skipped by default, since test code is full of fake secrets) |

The action sets up Java 21 for its own step, so it also changes the Java version for any later steps in the same job.

You can run the same scan locally:

```bash
mvn -q -DskipTests package
java -cp target/ast-reviewer-1.0.0.jar -Dloader.main=com.reviewer.cli.ScanCli \
  org.springframework.boot.loader.launch.PropertiesLauncher path/to/your/project
```

The scan only detects. The AI fix suggestions come from the webhook server described below.

---

## How Accurate Is It?

Measured, not guessed. A manual workflow (`.github/workflows/survey.yml`) runs the scanner on 31 open-source Java projects (27,552 files) and on the OWASP Benchmark, which ships an answer key.

**Hardcoded secrets: 83% fewer flags after tuning**

| | Flags across 31 projects |
| :--- | :--- |
| v1.0.0 | 156 |
| v1.1.0 | 27 |

Almost all of the 129 removed flags were names of secrets, not secrets: config keys (`"ssl.key.password"`), header names (`"X-Auth-Token"`), error messages, file paths, placeholders and regexes. In the 29 projects that are not security-training apps, 9 flags remain. Six are real hardcoded values (default passwords and a private key in h2, druid and kafka test fixtures) and three are still false alarms.

**SQL injection: weak on the OWASP Benchmark**

| Measure | Result |
| :--- | :--- |
| Real SQL injections caught | 94 of 272 (34.6%) |
| Safe code wrongly flagged | 76 of 232 (32.8%) |
| Precision | 55.3% |
| Benchmark score (caught % minus wrongly flagged %) | +1.8% |

This rule flags string concatenation passed to `execute`, `executeQuery` or `executeUpdate`. It does not track where the data came from, so it cannot tell user input from a constant, and it misses other query APIs. Treat its findings as "look at this line", not as confirmed bugs. Data-flow tracking is the next step.

Reproduce: Actions tab, "Survey open-source repos", Run workflow.

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
│   ├── cli/
│   │   └── ScanCli.java                 # Folder scanner used by the GitHub Action
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
│       ├── SecretHeuristics.java        # Filters out names of secrets (config keys, headers, messages)
│       └── SqlInjectionVisitor.java     # Dynamic SQL concatenation detector
├── src/test/java/com/reviewer/
│   ├── AstSecurityReviewerTest.java     # 37-case unit and regression suite
│   ├── ScanCliTest.java                 # Folder scanner tests
│   └── SecretNoiseTest.java             # False alarms found in the survey
├── survey/
│   ├── repos.txt                        # The 31 projects surveyed
│   └── benchmark_score.py               # Scores the SQL rule against OWASP Benchmark
├── action.yml                           # GitHub Action definition
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
Tests run: 57, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

The 57 tests cover:

- Folder scanning: finding both rules, skipping test folders, skipping files that are not valid Java
- Dynamic SQL string concatenation detection and false-positive filtering
- Literal credential assignments against variable-name sets
- Secret false alarms from the survey (config keys, headers, messages, paths, regexes) and real secrets that must still be flagged
- Code-block isolation and AST parse validation in `FixValidator`
- Valid, invalid, malformed and bypassed HMAC-SHA256 signatures

---

## Current Scope & Limitations

- **Syntax validation only:** `FixValidator` checks syntax with `StaticJavaParser.parseCompilationUnit()`. It does not do symbol resolution, type resolution or classpath compilation.
- **Two rules so far:** dynamic SQL concatenation and hardcoded string secrets. There is no data-flow or cross-file taint tracking, which is why the SQL rule scores low on the OWASP Benchmark (see above). Broader CWE coverage is not implemented.
- **Model size:** defaults to `qwen2.5-coder:1.5b` for fast local inference. Complex refactors may need a larger model, and suggestions should be reviewed by a person.

---

## Tech Stack

- **Language & framework:** Java 21, Spring Boot 3.3.4
- **AST parsing:** JavaParser
- **Local AI:** Ollama (qwen2.5-coder:1.5b)
- **Security:** HMAC-SHA256 (`javax.crypto.Mac`, constant-time `MessageDigest.isEqual`)
- **Deployment & testing:** Docker, Docker Compose, Maven, JUnit
