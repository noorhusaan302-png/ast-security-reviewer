package com.reviewer.engine;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.reviewer.model.Finding;
import com.reviewer.visitors.HardcodedSecretVisitor;
import com.reviewer.visitors.SqlInjectionVisitor;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: java -jar ast-reviewer.jar <path-to-target.java>");
            return;
        }

        File file = new File(args[0]);
        if (!file.exists()) {
            System.err.println("File not found: " + args[0]);
            return;
        }

        System.out.println("==================================================");
        System.out.println("  AST REVIEWER & AI REMEDIATION ENGINE");
        System.out.println("==================================================\n");
        System.out.println("Scanning AST for: " + file.getName() + " ...\n");

        CompilationUnit cu = StaticJavaParser.parse(file);
        List<Finding> findings = new ArrayList<>();

        cu.accept(new SqlInjectionVisitor(), findings);
        cu.accept(new HardcodedSecretVisitor(), findings);

        if (findings.isEmpty()) {
            System.out.println("No security findings detected in AST.");
            return;
        }

        System.out.println("Found " + findings.size() + " issue(s). Querying local LLM for fixes...\n");
        OllamaClient ollama = new OllamaClient("qwen2.5-coder:1.5b");

        for (Finding f : findings) {
            System.out.println("--------------------------------------------------");
            System.out.println("[" + f.severity() + "] Line " + f.lineNumber() + " (" + f.ruleName() + "): " + f.message());
            System.out.println("--> Code: " + f.codeSnippet() + "\n");
            System.out.println("Generating remediation via Ollama...");

            String rawFix = ollama.getFix(f.ruleName(), f.codeSnippet());
            String cleanedFix = FixValidator.cleanCode(rawFix);

            if (FixValidator.isValidJavaSnippet(rawFix)) {
                System.out.println("[AST VALIDATION PASSED] Proposed Fix:\n" + cleanedFix + "\n");
            } else {
                System.out.println("[AST VALIDATION FAILED] AI suggested syntactically invalid Java:\n" + rawFix + "\n");
            }
        }
    }
}
