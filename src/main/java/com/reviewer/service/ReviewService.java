package com.reviewer.service;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.reviewer.engine.FixValidator;
import com.reviewer.engine.OllamaClient;
import com.reviewer.model.Finding;
import com.reviewer.visitors.HardcodedSecretVisitor;
import com.reviewer.visitors.SqlInjectionVisitor;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class ReviewService {

    private final OllamaClient ollamaClient = new OllamaClient("qwen2.5-coder:1.5b");

    public record ReviewResult(Finding finding, String suggestedFix, boolean isValid) {}

    public List<ReviewResult> reviewSourceCode(String javaSource) {
        List<ReviewResult> results = new ArrayList<>();

        CompilationUnit cu;
        try {
            cu = StaticJavaParser.parse(javaSource);
        } catch (Exception e) {
            System.err.println("AST parsing failed: " + e.getMessage());
            return results;
        }

        List<Finding> findings = new ArrayList<>();
        new HardcodedSecretVisitor().visit(cu, findings);
        new SqlInjectionVisitor().visit(cu, findings);

        for (Finding finding : findings) {
            try {
                String rawFix = ollamaClient.getFix(finding.ruleName(), finding.codeSnippet());
                String cleanedFix = FixValidator.cleanCode(rawFix);
                boolean valid = FixValidator.isValidJavaSnippet(cleanedFix);
                results.add(new ReviewResult(finding, cleanedFix, valid));
            } catch (Exception ex) {
                System.err.println("LLM remediation failed for finding: " + finding.ruleName() + " - " + ex.getMessage());
                results.add(new ReviewResult(finding, "// Remediation error: " + ex.getMessage(), false));
            }
        }

        return results;
    }
}
