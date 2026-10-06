# Automated AST Security Reviewer & AI Remediation Engine

<p align="center">
  <img src="https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white" />
  <img src="https://img.shields.io/badge/Spring_Boot-3.3-6DB33F?style=for-the-badge&logo=springboot&logoColor=white" />
  <img src="https://img.shields.io/badge/Ollama-Qwen_2.5_Coder-black?style=for-the-badge&logo=ollama&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Security-HMAC--SHA256-red?style=for-the-badge" />
</p>

An automated static analysis and AI-driven code repair engine designed for continuous integration. It intercepts incoming GitHub pull requests, parses Java source code into an Abstract Syntax Tree (AST) using **JavaParser** to detect vulnerabilities deterministically, queries a local LLM (**Qwen 2.5 Coder via Ollama**) to synthesize patches on-premise, and enforces an in-memory compiler validation stage before posting inline code reviews back to GitHub.

---

## 🏗️ Architectural Flow

```text
       GitHub Pull Request Event
                  │
                  ▼  (HMAC-SHA256 Signature Checked)
┌─────────────────────────────────────────────────────────┐
│ Spring Boot Webhook Controller                          │
│                                                         │
│ 1. Cryptographic Handshake                              │
│    └── Verifies X-Hub-Signature-256 (constant-time)     │
│                                                         │
│ 2. Deterministic AST Analysis (JavaParser)              │
│    ├── SqlInjectionVisitor (dynamic string concat)      │
│    └── HardcodedSecretVisitor (entropy/credential regex)│
│                                                         │
│ 3. On-Premise AI Patch Synthesis                        │
│    └── Ollama Sidecar (qwen2.5-coder:1.5b)              │
│        (Zero proprietary source code leaves host)       │
│                                                         │
│ 4. Compiler-as-a-Judge Validation                       │
│    └── StaticJavaParser.parseCompilationUnit()          │
│        (Rejects syntax hallucinations & backticks)      │
│                                                         │
│ 5. Automated GitHub REST Review Dispatch                │
│    └── Posts inline comments directly onto the PR diff  │
└─────────────────────────────────────────────────────────┘
