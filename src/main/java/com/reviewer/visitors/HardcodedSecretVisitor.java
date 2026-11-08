package com.reviewer.visitors;

import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.reviewer.model.Finding;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Flags string literals that look like hardcoded credentials, either because the
 * variable name sounds like a secret (password, apiKey, token...) or because the
 * value itself looks like a key (AWS access key ID, PEM private key).
 * Values loaded at runtime (System.getenv, config lookups) and empty strings are ignored.
 */
public class HardcodedSecretVisitor extends VoidVisitorAdapter<List<Finding>> {

    private static final Set<String> SUSPICIOUS_NAMES = Set.of(
        "password", "passwd", "secret", "apikey", "api_key", "token", "auth_token",
        "accesskey", "access_key", "privatekey", "private_key", "credential"
    );

    // AWS access key IDs and PEM private key headers are secrets no matter what the variable is called
    private static final Pattern AWS_ACCESS_KEY = Pattern.compile("^(AKIA|ASIA)[0-9A-Z]{16}$");
    private static final Pattern PRIVATE_KEY_PEM = Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----");

    @Override
    public void visit(VariableDeclarator declarator, List<Finding> findings) {
        super.visit(declarator, findings);

        if (declarator.getInitializer().isEmpty()) return;
        if (!(declarator.getInitializer().get() instanceof StringLiteralExpr literal)) return;

        String value = literal.getValue();
        if (value.isBlank()) return; // "" is a placeholder, not a credential

        String varName = declarator.getNameAsString().toLowerCase();
        boolean suspiciousName = SUSPICIOUS_NAMES.stream().anyMatch(varName::contains);
        boolean suspiciousValue = AWS_ACCESS_KEY.matcher(value).matches()
                || PRIVATE_KEY_PEM.matcher(value).find();

        if (suspiciousName || suspiciousValue) {
            int line = declarator.getBegin().map(pos -> pos.line).orElse(-1);
            findings.add(new Finding(
                "HARDCODED_SECRET",
                "CRITICAL",
                line,
                "Possible hardcoded credential detected in variable '" + declarator.getNameAsString() + "'",
                declarator.toString()
            ));
        }
    }
}
