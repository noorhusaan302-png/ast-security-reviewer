# AST Security Reviewer & AI Remediation Engine

A Java tool that finds security issues in Java source code by analyzing its syntax tree, then asks a local LLM to suggest fixes and only keeps the suggestions that are valid Java.

It runs two ways: as a **command-line scanner** for a single file, and as a **Spring Boot webhook server** that accepts signed GitHub webhook requests.

**Tech:** Java 21 · Spring Boot · JavaParser · Ollama (`qwen2.5-coder:1.5b`) · Maven

---

## How It Works

```text
Java source file / webhook payload
        │
        ▼
[ HMAC-SHA256 check ]      rejects unsigned or spoofed webhook requests (401)
        │
        ▼
[ AST scan ]               JavaParser visitors flag SQL injection risks and hardcoded secrets
        │
        ▼
[ Local LLM fix ]          sends only the flagged code to Ollama for a suggested fix
        │
        ▼
[ Validation ]             re-parses the suggestion with JavaParser; invalid Java is rejected
```

**Why parse instead of regex?** The scanner reads code as a syntax tree, not as plain text. It can tell the difference between a string concatenation passed into `executeQuery(...)` and the same text sitting in a comment, which cuts down on false positives.

**Why validate the AI's output?** LLMs sometimes return broken code or chatty explanations. Every suggested fix is stripped of markdown and re-parsed. If it isn't valid Java, it's thrown out instead of shown to the user.

**Why a local model?** Fixes are generated with Ollama on your own machine, so the scanned source code never leaves it.

---

## Features

- **SQL injection detection:** flags queries built by concatenating strings, such as `executeQuery("... '" + userInput + "'")`.
- **Hardcoded secret detection:** flags API keys and passwords written directly into the code.
- **AI-suggested fixes:** for example, rewriting a concatenated query to use a `PreparedStatement`.
- **Syntax validation:** AI output that doesn't parse as Java is rejected.
- **Signed webhooks:** the server verifies GitHub's `X-Hub-Signature-256` header and returns `401 Unauthorized` for unsigned or invalid requests.

---

## Example Output

```text
==================================================
  AST REVIEWER & AI REMEDIATION ENGINE
==================================================

Scanning AST for: VulnerableApp.java ...
Found 2 issue(s). Querying local LLM for fixes...

--------------------------------------------------
[CRITICAL] Line 7 (SQL_INJECTION_RISK): Dynamic SQL query constructed via string concatenation.
--> Code: stmt.executeQuery("SELECT * FROM users WHERE username = '" + userInput + "'")

Generating remediation via Ollama...
[AST VALIDATION PASSED] Proposed Fix:
String sql = "SELECT * FROM users WHERE username = ?";
try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
    pstmt.setString(1, userInput);
    ResultSet rs = pstmt.executeQuery();
} catch (SQLException e) {
    // handle exception
}
```

---

## Getting Started

### Prerequisites

- Java 21+
- Maven 3.9+
- [Ollama](https://ollama.com/) running locally with the model pulled:

```bash
ollama run qwen2.5-coder:1.5b
```

### Run the command-line scanner

```bash
mvn compile exec:java -Dexec.mainClass="com.reviewer.engine.Main" -Dexec.args="VulnerableApp.java"
```

### Run the webhook server

Starts on port 8080:

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="--github.webhook.secret=supersecret123"
```

### Test the webhook

An unsigned request should be rejected with `401 Unauthorized`:

```bash
curl -i -X POST http://localhost:8080/api/webhook/github \
  -H "Content-Type: application/json" \
  -d '{"action": "opened"}'
```

A correctly signed request should be accepted:

```bash
PAYLOAD='{"action":"opened","code":"public class T { String s = \"sk-1234567890abcdef\"; }"}'
SECRET="supersecret123"
SIG="sha256=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')"

curl -i -X POST http://localhost:8080/api/webhook/github \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: $SIG" \
  -d "$PAYLOAD"
```

---

## Roadmap

- [ ] Fetch changed files from real GitHub pull requests
- [ ] Post fixes as inline review comments through the GitHub REST API
- [ ] More rules: unclosed resources, overly complex methods
- [ ] Unit tests for each rule and GitHub Actions CI
