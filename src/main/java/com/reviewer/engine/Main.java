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
    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Usage: java -jar ast-reviewer.jar <path-to-target.java>");
            System.exit(1);
        }

        File targetFile = new File(args[0]);
        if (!targetFile.exists()) {
            System.err.println("File not found: " + targetFile.getAbsolutePath());
            System.exit(1);
        }

        try {
            System.out.println("==================================================");
            System.out.println("  AST REVIEWER & AI REMEDIATION ENGINE");
            System.out.println("==================================================\n");
            System.out.println("Scanning AST for: " + targetFile.getName() + " ...\n");

            CompilationUnit cu = StaticJavaParser.parse(targetFile);
            List<Finding> findings = new ArrayList<>();

            // AST Rule Checking
            new HardcodedSecretVisitor().visit(cu, findings);
            new SqlInjectionVisitor().visit(cu, findings);

            if (findings.isEmpty()) {
                System.out.println("No AST violations detected. Code is clean!");
                return;
            }

            System.out.println("Found " + findings.size() + " issue(s). Querying local LLM for fixes...\n");

            OllamaClient ollama = new OllamaClient("qwen2.5-coder:1.5b");

            for (Finding finding : findings) {
                System.out.println("--------------------------------------------------");
                System.out.println(finding);
                System.out.println("Generating remediation via Ollama...");

                try {
                    String rawFix = ollama.getFix(finding.ruleName(), finding.codeSnippet());
                    String cleanedFix = FixValidator.cleanCode(rawFix);

                    boolean isValid = FixValidator.isValidJavaSnippet(cleanedFix);

                    if (isValid) {
                        System.out.println("[AST VALIDATION PASSED] Proposed Fix:");
                        System.out.println(cleanedFix);
                    } else {
                        System.out.println("[AST VALIDATION FAILED] AI suggested syntactically invalid Java:");
                        System.out.println(rawFix);
                    }
                } catch (Exception ex) {
                    System.err.println("Failed to get fix from Ollama: " + ex.getMessage());
                }
                System.out.println();
            }

        } catch (Exception e) {
            System.err.println("Failed to parse file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
